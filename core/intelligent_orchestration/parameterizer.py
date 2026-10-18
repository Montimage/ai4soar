"""
PlaybookParameterizer — fills {{variable}} placeholders in a CACAO template.

For each declared parameter:
  1. Look it up in the extracted IOCs dict by canonical name.
  2. Fall back to the parameter's default value if defined.
  3. Track required parameters that could not be filled (parameters_missing).
  4. Replace remaining {{name}} tokens with 'UNKNOWN_<NAME>' so the CACAO
     document stays structurally valid (no bare placeholders).

Values come from alert fields, which an attacker can often influence, and they are
substituted into shell commands. Each value is therefore checked against the
parameter's declared `type` first; a value that fails is treated as not found
(see _validate) and reported in parameters_rejected.
"""

import copy
import json
import ipaddress
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")

# `string`: identifiers used as bare shell arguments (usernames, hostnames, emails):
# no whitespace or shell metacharacters, and no leading "-" (it would be read as an
# option, e.g. a username of "x -G root" or "-G").
_SAFE_STRING = re.compile(r"^[A-Za-z0-9_.@:/+=,][A-Za-z0-9_.@:/+=,-]{0,252}$")
# `text`: free text (subjects, paths, process names, URLs) that templates only use
# inside single quotes or JSON strings: anything printable except quotes, backslash,
# $ and backtick, which could close the quoting or expand.
_SAFE_TEXT = re.compile(r"^[^'\"\\$`\x00-\x1f\x7f]{1,1024}$")


_SAFE_URL = re.compile(r"^https?://[^\s'\"\\$`<>]{1,2048}$")

# STIX identity that CACAO's required `created_by` points to (fixed: "AI4SOAR")
AI4SOAR_IDENTITY = f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, 'https://ai4soar.montimage.eu')}"
_SPEC_ID = re.compile(
    r"^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")


def _validate(value: Any, ptype: str):
    """Return the value (normalised) if it is safe for its declared type, else None."""
    text = str(value).strip()
    if ptype == "ipv4":
        try:
            return str(ipaddress.IPv4Address(text))
        except ValueError:
            return None
    if ptype == "integer":
        return int(text) if re.fullmatch(r"\d{1,9}", text) else None
    if ptype == "text":
        return text if _SAFE_TEXT.match(text) else None
    if ptype == "url":
        return text if _SAFE_URL.match(text) else None
    return text if _SAFE_STRING.match(text) else None


@dataclass
class ParameterizedPlaybook:
    id: str
    name: str
    techniques: List[str]
    parameters_filled: Dict[str, Any]
    parameters_missing: List[str]
    cacao: Dict[str, Any]
    parameters_rejected: List[str] = field(default_factory=list)
    # declared optional, and the alert / .env had no (usable) value for them
    parameters_optional_unfilled: List[str] = field(default_factory=list)
    # secret: true parameters (API keys): left as {{name}} here, filled from .env only in
    # the workflow deployed to the SOAR platform (fill_secrets), so the key never shows up
    # in the CACAO the UI displays, copies or stores
    parameters_secret: List[str] = field(default_factory=list)
    template_hash: str = ""
    # filled from .env (env: parameters), not from the alert: deployment settings
    parameters_settings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "id":                 self.id,
            "name":               self.name,
            "techniques":         self.techniques,
            "parameters_filled":  self.parameters_filled,
            "parameters_missing": self.parameters_missing,
            "parameters_rejected": self.parameters_rejected,
            "parameters_optional_unfilled": self.parameters_optional_unfilled,
            "parameters_secret":  self.parameters_secret,
            "template_hash":      self.template_hash,
            "parameters_settings": self.parameters_settings,
            "cacao":              self.cacao,
        }


class PlaybookParameterizer:

    def parameterize(
        self,
        template: Dict,
        iocs: Dict[str, Any],
        alert: Dict[str, Any] = None,
    ) -> ParameterizedPlaybook:
        """
        Inject IOC values into the CACAO template.

        Resolution order for each declared parameter:
          1. Canonical IOC dict (pre-extracted by IOCExtractor)
          2. `sources` paths declared in the template parameter spec,
             resolved directly against the raw alert — lets templates be
             self-describing for vendor-specific fields (e.g. probe_id).
          3. Parameter default value.

        Returns a ParameterizedPlaybook with:
          - parameters_filled: IOC values that were injected
          - parameters_missing: required params that could not be filled
          - cacao: fully substituted CACAO dict (no {{}} tokens remain)
        """
        params_spec: Dict[str, Any] = template.get("parameters", {})
        filled:   Dict[str, Any] = {}
        missing:  List[str]      = []
        rejected: List[str]      = []

        secret: List[str] = []
        for param_name, spec in params_spec.items():
            if spec.get("secret"):
                secret.append(param_name)
                continue
            # Deployment settings (e.g. the ticketing API URL) come from the environment,
            # never from the alert
            value = (os.getenv(spec["env"]) or None) if spec.get("env") else iocs.get(param_name)

            # Fallback: resolve `sources` paths from the template against the raw alert
            if value is None and alert and spec.get("sources") and not spec.get("env"):
                for path in spec["sources"]:
                    value = _get_nested(alert, path.split("."))
                    if value is not None and value != "":
                        break
                    value = None

            if value is not None:
                safe = _validate(value, spec.get("type", "string"))
                if safe is None:
                    logger.warning(
                        f"[Parameterizer] {template['id']}: rejected unsafe value for "
                        f"'{param_name}' ({spec.get('type', 'string')}): {str(value)[:80]!r}"
                    )
                    rejected.append(param_name)
                value = safe

            if value is None and "default" in spec:
                value = spec["default"]
            if value is not None:
                filled[param_name] = value
            elif spec.get("required", False):
                missing.append(param_name)

        # Build substitution map: filled values + UNKNOWN_X for missing
        substitution = dict(filled)
        for m in missing:
            substitution[m] = f"UNKNOWN_{m.upper()}"

        cacao_filled = _fill_recursive(copy.deepcopy(template.get("cacao", {})), substitution)
        cacao_filled = _to_spec_ids(cacao_filled, template["id"])
        cacao_filled.setdefault("created_by", AI4SOAR_IDENTITY)
        cacao_filled["labels"] = template_labels(template, cacao_filled)
        pb_name      = _fill_str(template.get("name", template["id"]), substitution)

        # Ensure CACAO 2.0 compliance: proper UUID id + timestamps
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        cacao_filled["id"]       = f"playbook--{uuid.uuid4()}"
        cacao_filled["created"]  = now
        cacao_filled["modified"] = now

        if missing:
            logger.warning(
                f"[Parameterizer] {template['id']}: required params not found "
                f"in IOCs — {missing}"
            )

        return ParameterizedPlaybook(
            id=template["id"],
            name=pb_name,
            techniques=template.get("techniques", []),
            parameters_filled=filled,
            parameters_missing=missing,
            cacao=cacao_filled,
            parameters_rejected=rejected,
            parameters_optional_unfilled=[
                n for n, spec in params_spec.items()
                if n not in filled and not spec.get("required", False) and not spec.get("secret")],
            parameters_secret=secret,
            template_hash=template_hash(template),
            parameters_settings=[n for n, spec in params_spec.items()
                                 if spec.get("env") and not spec.get("secret") and n in filled],
        )


def template_hash(template: Dict) -> str:
    """Fingerprint of a template's content (parameters and CACAO): a saved recommendation
    built from another fingerprint is out of date."""
    import hashlib
    body = json.dumps({"parameters": template.get("parameters"), "cacao": template.get("cacao")},
                      sort_keys=True, default=str)
    return hashlib.sha1(body.encode()).hexdigest()[:12]


def secret_settings(include_plain: bool = False) -> Dict[str, str]:
    """{parameter name: env variable} of every secret parameter in the library (with
    include_plain, of every .env-sourced parameter)."""
    import glob
    import yaml
    from core.config import config
    out: Dict[str, str] = {}
    for path in glob.glob(os.path.join(config.playbook_library.path, "*.y*ml")):
        with open(path, encoding="utf-8") as fh:
            for name, spec in ((yaml.safe_load(fh) or {}).get("parameters") or {}).items():
                if (spec or {}).get("env") and (include_plain or spec.get("secret")):
                    out[name] = spec["env"]
    return out


def fill_secrets(cacao: Dict, include_plain: bool = True) -> Dict:
    """A copy of the playbook with .env settings filled: secrets (API keys) are only ever
    filled here, for the workflow sent to the SOAR platform; plain settings (ticketing
    URL, firewall host) are filled at recommendation time too, and again here so that a
    recommendation made before a setting was set still deploys with its current value."""
    text = json.dumps(cacao)
    for name, env in secret_settings(include_plain).items():
        if os.getenv(env):
            text = re.sub(r"\{\{\s*" + re.escape(name) + r"\s*\}\}",
                          lambda _m: json.dumps(os.environ[env])[1:-1], text)
    return json.loads(text)


def template_labels(template: Dict, cacao: Dict = None) -> List[str]:
    """CACAO labels of a library playbook: its own, then the template's ATT&CK techniques
    and tactics (they become the Shuffle workflow's tags)."""
    out: List[str] = []
    for label in [*((cacao or template.get("cacao") or {}).get("labels") or []),
                  *(template.get("techniques") or []), *(template.get("tactics") or [])]:
        if label not in out:
            out.append(label)
    return out


def _to_spec_ids(cacao: Dict, template_id: str) -> Dict:
    """Give workflow steps CACAO 2.0 identifiers ("<type>--<uuid>").

    Templates use readable keys (step--block-ip) for authoring; the spec requires
    identifiers. UUIDv5 of template id + key keeps them stable across runs. Every
    reference (workflow_start, on_success, next_steps, ...) is an exact string match
    on a key, so replacing exact matches inside the workflow rewrites all of them.
    """
    workflow = cacao.get("workflow") or {}
    mapping = {
        key: f"{step.get('type', 'action')}--{uuid.uuid5(uuid.NAMESPACE_URL, f'ai4soar:{template_id}:{key}')}"
        for key, step in workflow.items()
        if not _SPEC_ID.match(key) and isinstance(step, dict)
    }
    if not mapping:
        return cacao

    def remap(obj: Any) -> Any:
        if isinstance(obj, str):
            return mapping.get(obj, obj)
        if isinstance(obj, dict):
            return {k: remap(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [remap(v) for v in obj]
        return obj

    cacao["workflow"] = {mapping.get(k, k): remap(v) for k, v in workflow.items()}
    for key in ("workflow_start", "workflow_exception"):
        if key in cacao:
            cacao[key] = mapping.get(cacao[key], cacao[key])
    return cacao


def _get_nested(obj: Any, keys: List[str]) -> Any:
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _fill_recursive(obj: Any, sub: Dict[str, Any]) -> Any:
    if isinstance(obj, str):
        return _fill_str(obj, sub)
    if isinstance(obj, dict):
        return {k: _fill_recursive(v, sub) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill_recursive(item, sub) for item in obj]
    return obj


def _fill_str(s: str, sub: Dict[str, Any]) -> str:
    return _PLACEHOLDER.sub(lambda m: str(sub.get(m.group(1), m.group(0))), s)
