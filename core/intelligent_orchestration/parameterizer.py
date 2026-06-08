"""
PlaybookParameterizer — fills {{variable}} placeholders in a CACAO template.

For each declared parameter:
  1. Look it up in the extracted IOCs dict by canonical name.
  2. Fall back to the parameter's default value if defined.
  3. Track required parameters that could not be filled (parameters_missing).
  4. Replace remaining {{name}} tokens with 'UNKNOWN_<NAME>' so the CACAO
     document stays structurally valid (no bare placeholders).
"""

import copy
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")


@dataclass
class ParameterizedPlaybook:
    id: str
    name: str
    techniques: List[str]
    parameters_filled: Dict[str, Any]
    parameters_missing: List[str]
    cacao: Dict[str, Any]

    def to_dict(self) -> Dict:
        return {
            "id":                 self.id,
            "name":               self.name,
            "techniques":         self.techniques,
            "parameters_filled":  self.parameters_filled,
            "parameters_missing": self.parameters_missing,
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
        filled:  Dict[str, Any] = {}
        missing: List[str]      = []

        for param_name, spec in params_spec.items():
            value = iocs.get(param_name)

            # Fallback: resolve `sources` paths from the template against the raw alert
            if value is None and alert and spec.get("sources"):
                for path in spec["sources"]:
                    value = _get_nested(alert, path.split("."))
                    if value is not None and value != "":
                        break
                    value = None

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
        )


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
