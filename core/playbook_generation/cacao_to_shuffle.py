"""
CACAO 2.0 playbook -> Shuffle workflow JSON (the format Shuffle exports and imports).

Reference format: small workflows built by hand in Shuffle and exported
(datasets/cacao_examples/test_1.json). A Shuffle workflow is a list of `actions` (nodes), `branches` (edges) and a `start`
action id; there is no start/end node, so CACAO `start` and `end` steps are folded away
and the step after `start` becomes the Shuffle start node.

How each CACAO action step is bound to a Shuffle app action, first match wins:

  1. step_extensions[SHUFFLE_EXTENSION_ID]  explicit binding: app_name, app_version,
                                            action, parameters. Lossless, so a workflow
                                            converted from this format comes back as-is.
                                            Any action of any app (e.g. Shuffle Tools
                                            parse_ioc, regex_capture_group, set_json_key,
                                            send_sms_shuffle); parameters are checked
                                            against the app's api.yaml.
  2. bash commands                         Shuffle Tools `run_ssh_command` on the machine
                                            the step acts on: its first ssh/linux target
                                            (else its agent) with a real address; host and
                                            port from the definition, credentials from its
                                            authentication_info or ssh_defaults, or left
                                            empty for the operator to fill in Shuffle.
                                            Without such a machine (or at a loopback
                                            address: "where the playbook runs"),
                                            `execute_bash` in Shuffle's Tools app.
  3. http-api command                       the `http` app, action = HTTP method, host
                                            taken from the step's http-api target;
                                            http-basic/user-auth -> username/password,
                                            oauth2 -> Authorization header, content_b64
                                            decoded into the body.
  4. openc2-http command                    http POST with the OpenC2 content type.
  5. ssh command                            `run_ssh_command` on the ssh/linux target
                                            (execute_bash when there is none).
  6. powershell command                     `run_ssh_command` running
                                            powershell -EncodedCommand on an ssh target
                                            (Windows + OpenSSH); else an echo.
  7. manual command                         `repeat_back_to_me` with the instruction
                                            (Shuffle does not pause for it).
  8. caldera-cmd, elastic, kestrel, sigma,  `repeat_back_to_me`, echoing the command for
     yara, jupyter                          an analyst to rebind (no Shuffle app).

Control flow: a workflow's branches carry Shuffle conditions (source, operator,
destination; all must hold; configuration=true negates one, as the editor's NOT).
  if-condition      pass-through node; on_true gets the condition, on_false its negation.
                    The STIX-pattern comparison must test a playbook variable
                    ([__x__:value = 'v'], >, <, >=, <=, !=, LIKE, MATCHES, IN, NOT, AND);
                    OR or STIX object paths cannot be expressed: both branches then run.
  switch-condition  one branch per case (equals); "default" = does not equal every case.
  parallel          one branch per next_steps entry (Shuffle runs them in parallel).
  while-condition,  not representable (no loops / no subflow binding): the body runs
  playbook-action   once, or an echo, with a warning.
Shuffle Tools if_else_routing is declared in its api.yaml but not implemented in 1.2.0,
so conditions are never routed through it.

dry_run=True turns (2) and (3) into echoes as well, so a dry-run workflow changes
nothing outside Shuffle. Path D commands are LLM-written and review-required, so
convert its output with dry_run until someone has read them.

ssh_defaults fills what a step's ssh/linux machine leaves open (host, port, user_name,
password, private_key_file_id); a loopback address counts as open, since 127.0.0.1
inside Shuffle's app container is that container, not the machine meant. Without an
ssh_defaults host, such a step runs as execute_bash in Shuffle's Tools app.
Note that `execute_bash` runs inside Shuffle's Tools app container, not on the
alerting host; give the step an ssh/linux target to act on a real machine.

Data flow: a variable a step lists in CACAO `out_args` becomes a reference to that
step's Shuffle node ($label), refined by the extension's optional
"outputs": {"__var__": "<path>"} (e.g. "#0.data" -> $extract_ip.#0.data). The extension
may hold only "outputs" (no app_name): the step is then converted as usual, e.g. an
http-api lookup whose JSON answer feeds a condition
("outputs": {"__vt_malicious__": "body.data.attributes.last_analysis_stats.malicious"}).
Every other variable becomes $exec.<name>, the workflow's execution argument.

Node templates (actions, parameters, icons) come from three layers, later wins:
  1. data/shuffle_python_apps.json  built from Shuffle's public app definitions
     (github.com/Shuffle/python-apps, */*/api.yaml) with --sync-python-apps. Covers
     every action of every app, but has no app_id: Shuffle assigns each app a random
     UUID when an instance loads it (backend/go-app/walkoff.go).
  2. data/shuffle_app_catalog.json  learned from workflows exported from our Shuffle
     instance with --learn-from; supplies the real app_id.
  3. --live-catalog                 app ids and icons read from the running instance.

Not representable in Shuffle and reported in `warnings` instead of silently dropped:
on_failure links (Shuffle branches fire on success), and the condition of
if/while/switch steps (they become a node that fans out to every outcome).
"""

import argparse
import base64
import copy
import json
import logging
import re
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SHUFFLE_EXTENSION_ID = "extension-definition--b3e2ef12-32fb-44cd-bfb3-1de80aea9273"

SHUFFLE_EXTENSION_DEFINITION = {
    "type": "extension-definition",
    "name": "AI4SOAR Shuffle binding",
    "description": "Binds a CACAO action step to one Shuffle app action. Read by "
                   "core/playbook_generation/cacao_to_shuffle.py; other CACAO "
                   "consumers can ignore it.",
    "created_by": "identity--69176b24-3592-4232-882c-4bb80ade052a",
    "schema": "Object with app_name (string), app_version (string), action (Shuffle "
              "action name) and parameters (map of parameter name to value).",
    "version": "1.0.0",
}

TOOLS_APP = ("Shuffle Tools", "1.2.0")
HTTP_APP = ("http", "1.4.0")

CATALOG_PATH = Path(__file__).resolve().parents[2] / "data" / "shuffle_app_catalog.json"
PYTHON_APPS_PATH = CATALOG_PATH.with_name("shuffle_python_apps.json")
PYTHON_APPS_REPO = "https://github.com/Shuffle/python-apps"

# Parameter order and `required` flags as Shuffle exports them, for the actions we emit.
ACTION_PARAMS: Dict[Tuple[str, str], Dict[str, bool]] = {
    ("Shuffle Tools", "repeat_back_to_me"): {"call": True},
    ("Shuffle Tools", "execute_bash"): {"code": True, "shuffle_input": False},
}

# (app_name, app_version) -> {"app_id", "large_image", "action_images": {action: image},
#                             "action_templates": {action: exported node, ids stripped}}
Catalog = Dict[Tuple[str, str], Dict[str, Any]]

# Per-node fields of an exported action; everything else is copied into templates.
_INSTANCE_FIELDS = ("id", "_id", "id_", "_id_", "label", "position", "circleId",
                    "isStartNode", "source_workflow")

# Deterministic ids: converting the same playbook twice gives the same workflow.
_NS = uuid.UUID("0572ab29-6419-43a8-9ebc-45a5f49b961e")
_CACAO_VAR = re.compile(r"__([A-Za-z0-9_]+?)__(?::value)?")
_TEMPLATE_VAR = re.compile(r"\{\{\s*(\w+)\s*\}\}")

_X0, _Y0, _DX, _DY = 350.0, 230.0, 260.0, 190.0


# A comparison of the STIX patterning grammar (CACAO if/while conditions), e.g.
# [__severity__:value = 'high'], [__score__ >= 7], __host__ NOT LIKE 'web-%'. C-style ==
# is accepted too (LLM-written playbooks use it).
_COMPARISON = re.compile(
    r"^\s*(?P<lhs>\S+?)\s*(?P<neg>\bNOT\s+)?(?P<op>==|!=|>=|<=|=|>|<|\bMATCHES\b|\bLIKE\b|\bIN\b)\s*(?P<rhs>.+?)\s*$",
    re.I)
# STIX/C operator -> (Shuffle condition, negated). Shuffle has no >= / <=: they are the
# negation of < / >.
_OPS = {"=": ("equals", False), "==": ("equals", False), "!=": ("does not equal", False),
        ">": ("larger than", False), "<": ("less than", False),
        ">=": ("less than", True), "<=": ("larger than", True),
        "MATCHES": ("matches regex", False), "IN": ("contains_any_of", False)}


def _literal(text: str) -> str:
    """A STIX literal: 'quoted string' (with \\' escapes), number or boolean -> plain text."""
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        body = text[1:-1].replace("\\'", "'").replace('\\"', '"')
        return body.replace("\\\\", "\\")   # STIX escapes a backslash as \\
    return text


def _split_top(expr: str, word: str) -> List[str]:
    """Split on a boolean keyword (AND / OR) outside quotes and parentheses."""
    parts, depth, quote, last = [], 0, "", 0
    pat = re.compile(rf"\s+{word}\s+", re.I)
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            quote = "" if ch == quote and expr[i - 1] != "\\" else quote
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0:
            m = pat.match(expr, i)
            if m:
                parts.append(expr[last:i]); last = i = m.end(); continue
        i += 1
    parts.append(expr[last:])
    return [p.strip() for p in parts if p.strip()]


def parse_condition(expr: str) -> Tuple[Optional[List[Tuple[str, str, str, bool]]], str]:
    """CACAO condition -> ([(variable expr, shuffle op, value, negated), ...] ANDed, "") or
    (None, reason) when Shuffle cannot express it. Only comparisons on CACAO variables
    (__name__) have a value at run time; a pattern over STIX objects has nothing to compare."""
    body = (expr or "").strip()
    if body.startswith("[") and body.endswith("]"):
        body = body[1:-1].strip()
    if not body:
        return None, "empty condition"
    if len(_split_top(body, "OR")) > 1:
        return None, "OR is not expressible (a Shuffle branch ANDs its conditions)"
    if re.search(r"\b(FOLLOWEDBY|WITHIN|REPEATS|START|STOP)\b", body, re.I):
        return None, "STIX qualifiers/observation operators have no Shuffle equivalent"
    out = []
    for part in _split_top(body, "AND"):
        m = _COMPARISON.match(part.strip("[] "))
        if not m:
            return None, f"'{part}' is not a comparison"
        lhs, op, rhs = m.group("lhs"), m.group("op").upper(), m.group("rhs")
        if not _CACAO_VAR.search(lhs):
            return None, f"'{lhs}' is a STIX object path, not a playbook variable"
        negate = bool(m.group("neg"))
        if op == "LIKE":
            pat = _literal(rhs)
            core = pat.strip("%")
            if "%" not in core and "_" not in core:
                shuffle_op = ("contains" if pat.startswith("%") and pat.endswith("%") and len(pat) > 1
                              else "endswith" if pat.startswith("%")
                              else "startswith" if pat.endswith("%") else "equals")
                out.append((lhs, shuffle_op, core, negate))
            else:
                rx = "^" + re.escape(pat).replace("%", ".*").replace("_", ".") + "$"
                out.append((lhs, "matches regex", rx, negate))
            continue
        shuffle_op, flip = _OPS[op]
        # IN ('a', 'b'): Shuffle's contains_any_of takes a comma-separated list
        value = (",".join(_literal(v) for v in rhs.strip().strip("()").split(","))
                 if op == "IN" else _literal(rhs))
        out.append((lhs, shuffle_op, value, negate != flip))
    return out, ""


class ConversionError(ValueError):
    """The playbook cannot be turned into a Shuffle workflow at all."""


def _uuid_part(cacao_id: str) -> str:
    return cacao_id.split("--", 1)[1] if "--" in cacao_id else cacao_id


def _derived_id(*parts: str) -> str:
    # Deterministic, but shaped like the random v4 ids the Shuffle editor creates.
    return str(uuid.UUID(bytes=uuid.uuid5(_NS, "|".join(parts)).bytes, version=4))


def _node_id(step_id: str) -> str:
    """Reuse the step's UUID; library steps like 'step--block-ip' get a derived one."""
    part = _uuid_part(step_id)
    try:
        return str(uuid.UUID(part))
    except ValueError:
        return _derived_id(step_id)


def load_catalog(path: Path = CATALOG_PATH) -> Catalog:
    if not path.exists():
        return {}
    with open(path) as f:
        apps = json.load(f).get("apps", [])
    return {(a["app_name"], a["app_version"]): a for a in apps}


def _merge(base: Catalog, overlay: Catalog) -> Catalog:
    """overlay wins field by field; action templates and images merge per action."""
    out = copy.deepcopy(base)
    for key, entry in overlay.items():
        merged = out.setdefault(key, {})
        for field, value in entry.items():
            if isinstance(value, dict) and isinstance(merged.get(field), dict):
                merged[field] = {**merged[field], **value}
            elif value or field not in merged:
                merged[field] = value
    return out


def _derive_from_exports(python_apps: Catalog, exported: Catalog) -> Catalog:
    """Give every action of an exported app a template shaped like the exported nodes.

    An export only holds the actions someone placed in that workflow (e.g. http GET), and
    templates built from api.yaml miss fields the editor sets. So an action of the same
    app that the export lacks (http POST) is built from an exported node: all its node
    fields, with the action's own name, description and parameters, each parameter in
    the exported parameter shape.
    """
    out = copy.deepcopy(exported)
    for key, entry in exported.items():
        templates = entry.get("action_templates") or {}
        base = next(iter(templates.values()), None)
        if not base:
            continue
        param_shape = next((prm for prm in base.get("parameters") or []), {})
        for action, spec in ((python_apps.get(key) or {}).get("action_templates") or {}).items():
            if action in templates:
                continue
            tpl = copy.deepcopy(base)
            tpl["name"] = action
            tpl["description"] = spec.get("description", "")
            tpl["parameters"] = [
                {**{k: v for k, v in param_shape.items()},
                 **{k: prm.get(k) for k in ("name", "description", "example", "multiline",
                                            "multiselect", "options", "required",
                                            "configuration", "schema")},
                 "value": prm.get("value", ""), "id": "", "error": ""}
                for prm in spec.get("parameters") or []]
            out[key]["action_templates"][action] = tpl
    return out


def load_full_catalog() -> Catalog:
    python_apps = load_catalog(PYTHON_APPS_PATH)
    return _merge(python_apps, _derive_from_exports(python_apps, load_catalog(CATALOG_PATH)))


def _api_param(p: Dict, configuration: bool = False) -> Dict:
    """One api.yaml parameter -> the parameter object the Shuffle editor exports."""
    return {
        "description": p.get("description", ""),
        "id": "",
        "name": p["name"],
        "example": str(p.get("example", "") or ""),
        "value": str(p.get("value", "") or ""),
        "multiline": bool(p.get("multiline", False)),
        "multiselect": bool(p.get("multiselect", False)),
        # YAML booleans come back as True/False; Shuffle's app loader writes "true"/"false"
        "options": ([str(o).lower() if isinstance(o, bool) else str(o) for o in p["options"]]
                    if p.get("options") else None),
        "action_field": "",
        "variant": "",
        "required": bool(p.get("required", False)),
        "configuration": configuration,
        "tags": None,
        "schema": {"type": (p.get("schema") or {}).get("type") or ""},
        "skip_multicheck": False,
        "value_replace": None,
        "unique_toggled": False,
        "error": "",
        "hidden": False,
        "custom_value": False,
    }


def _action_template(key: Tuple[str, str], action: Dict, params: List[Dict], category: str,
                     example: str = "", app_id: str = "", generated: bool = False) -> Dict:
    """A node as the editor creates it when an action is dropped on the canvas."""
    return {
        "app_name": key[0],
        "app_version": key[1],
        "description": action.get("description", ""),
        "app_id": app_id,
        "errors": [],
        "is_valid": True,
        "sharing": True,
        "public": True,
        "generated": generated,
        "environment": "Shuffle",
        "name": action["name"],
        "parameters": params,
        "execution_variable": {"description": "", "id": "", "name": "", "value": ""},
        "authentication_id": "",
        "category": category,
        "reference_url": "",
        "sub_action": False,
        "run_magic_output": False,
        "run_magic_input": False,
        "execution_delay": 0,
        "parent_controlled": False,
        "type": "ACTION",
        "authentication": [],
        "selectedAuthentication": {},
        "isValid": True,
        # Node fields the editor sets on a freshly placed action
        "category_label": None,
        "suggestion": False,
        "source_workflow": "",
        "source_execution": "",
        "example": example,
    }


def catalog_from_python_apps(repo_dir: Path) -> Catalog:
    """Build node templates for every action of every app in a python-apps checkout."""
    import yaml

    catalog: Catalog = {}
    for path in sorted(Path(repo_dir).glob("*/*/api.yaml")):
        try:
            app = yaml.safe_load(path.read_text())
            key = (app["name"], str(app["app_version"]))
        except Exception as exc:  # a few community apps carry malformed yaml
            logger.warning("skipping %s: %s", path, exc)
            continue
        auth = app.get("authentication") or {}
        auth_params = (auth.get("parameters") or []) if auth.get("required") else []
        category = (app.get("categories") or ["Other"])[0]
        templates = {}
        for action in app.get("actions") or []:
            params = [_api_param(p) for p in action.get("parameters") or []]
            # As Shuffle's app loader does: auth fields become configuration
            # parameters, prepended unless the action already declares them.
            if not action.get("auth_not_required"):
                names = {prm["name"] for prm in params}
                for prm in params:
                    if any(a["name"] == prm["name"] for a in auth_params):
                        prm["configuration"] = True
                params = [_api_param(a, configuration=True)
                          for a in auth_params if a["name"] not in names] + params
            templates[action["name"]] = _action_template(
                key, action, params, category,
                str(((action.get("returns") or {}).get("example")) or ""))
        catalog[key] = {"app_name": key[0], "app_version": key[1], "app_id": "",
                        "large_image": app.get("large_image", ""),
                        "action_images": {}, "action_templates": templates}
    return catalog


def sync_python_apps(repo_dir: Optional[Path] = None, out: Path = PYTHON_APPS_PATH) -> Catalog:
    """Fetch the api.yaml files of python-apps (sparse clone) and rebuild `out`."""
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        if repo_dir is None:
            repo_dir = Path(tmp) / "python-apps"
            subprocess.run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none",
                            "--sparse", PYTHON_APPS_REPO, str(repo_dir)], check=True)
            subprocess.run(["git", "-C", str(repo_dir), "sparse-checkout", "set",
                            "--no-cone", "/*/*/api.yaml"], check=True)
        catalog = catalog_from_python_apps(repo_dir)
    save_catalog(catalog, out)
    return catalog


def learn_catalog(export: Dict, catalog: Catalog) -> Catalog:
    """Merge app ids and node icons found in a Shuffle workflow export into catalog."""
    for a in export.get("actions", []):
        key = (a.get("app_name", ""), a.get("app_version", ""))
        if not all(key) or not a.get("app_id"):
            continue
        entry = catalog.setdefault(key, {"app_name": key[0], "app_version": key[1],
                                         "action_images": {}})
        entry["app_id"] = a["app_id"]
        image = a.get("large_image", "")
        # The app icon is a PNG; some actions (execute_bash) carry their own SVG.
        if image.startswith("data:image/png"):
            entry.setdefault("large_image", image)
        elif image:
            entry["action_images"][a.get("name", "")] = image
        # Keep the whole node as the template for this action, so generated nodes carry
        # every field the Shuffle editor sets. Shuffle exports the start node with
        # thinner parameter metadata, so any other node is preferred as the template.
        templates = entry.setdefault("action_templates", {})
        if a.get("name") and (a["name"] not in templates or not a.get("isStartNode")):
            tpl = {k: v for k, v in a.items() if k not in _INSTANCE_FIELDS}
            tpl["parameters"] = [{**prm, "value": ""} for prm in a.get("parameters") or []]
            templates[a["name"]] = tpl
    return catalog


def save_catalog(catalog: Catalog, path: Path = CATALOG_PATH) -> None:
    with open(path, "w") as f:
        json.dump({"apps": [catalog[k] for k in sorted(catalog)]}, f, indent=2)
        f.write("\n")


def fetch_app_catalog(shuffle_config=None) -> Catalog:
    """Read app ids and icons from a live Shuffle instance (GET /apps); for apps generated
    in that instance (OpenAPI apps, e.g. Virustotal_v3), which are not in the public app
    definitions, also the node templates of their actions."""
    import requests

    if shuffle_config is None:
        from core.config import config
        shuffle_config = config.shuffle
    resp = requests.get(f"{shuffle_config.api_base_url}/apps",
                        headers=shuffle_config.get_headers(), timeout=30)
    resp.raise_for_status()
    catalog: Catalog = {}
    for a in resp.json():
        if not a.get("id"):
            continue
        key = (a.get("name", ""), a.get("app_version", ""))
        entry = {"app_name": key[0], "app_version": key[1], "app_id": a["id"],
                 "large_image": a.get("large_image", ""), "action_images": {}}
        if a.get("generated"):
            category = (a.get("categories") or ["Other"])[0]
            entry["action_templates"] = {
                act["name"]: _action_template(
                    key, act, [{**_api_param(p, bool(p.get("configuration"))),
                                "value": str(p.get("value") or "")}
                               for p in act.get("parameters") or []],
                    category, app_id=a["id"], generated=True)
                for act in a.get("actions") or [] if act.get("name")}
        catalog[key] = entry
    return catalog


def _command_text(command: Dict) -> str:
    """command, or command_b64 decoded (CACAO uses it for commands with special characters)."""
    if command.get("command"):
        return command["command"]
    if command.get("command_b64"):
        try:
            return base64.b64decode(command["command_b64"]).decode("utf-8")
        except Exception:
            return command["command_b64"]
    return ""


def _content_text(command: Dict) -> str:
    if command.get("content"):
        return command["content"]
    if command.get("content_b64"):
        try:
            return base64.b64decode(command["content_b64"]).decode("utf-8")
        except Exception:
            return ""
    return ""


class _Converter:
    def __init__(self, cacao: Dict, catalog: Catalog, dry_run: bool,
                 ssh_defaults: Optional[Dict[str, str]] = None):
        self.cacao = cacao
        self.dry_run = dry_run
        self.ssh_defaults = {k: str(v) for k, v in (ssh_defaults or {}).items() if v}
        self._creds_warned: set = set()
        self.workflow: Dict[str, Dict] = cacao.get("workflow") or {}
        self.variables: Dict[str, Dict] = cacao.get("playbook_variables") or {}
        self.definitions: Dict[str, Dict] = {**(cacao.get("agent_definitions") or {}),
                                             **(cacao.get("target_definitions") or {})}
        self.auth_infos: Dict[str, Dict] = cacao.get("authentication_info_definitions") or {}
        # __var__ -> (producing step id, path into its output) from out_args
        self.outputs: Dict[str, Tuple[str, str]] = {}
        for sid, st in self.workflow.items():
            paths = ((st or {}).get("step_extensions") or {}).get(
                SHUFFLE_EXTENSION_ID, {}).get("outputs") or {}
            for var in (st or {}).get("out_args") or []:
                self.outputs[var] = (sid, paths.get(var, ""))
        self.catalog = catalog
        self.actions: List[Dict] = []
        self.branches: List[Dict] = []
        self.warnings: List[str] = []
        self.labels: set = set()
        # CACAO step id -> (first, last) Shuffle node id; a multi-command step is a chain
        self.span: Dict[str, Tuple[str, str]] = {}
        # if/switch step id -> {successor step id: [Shuffle conditions]} (see _routing)
        self.routes: Dict[str, Dict[str, List[Dict]]] = {}

    # -- values ---------------------------------------------------------------

    def _variable(self, m: re.Match) -> str:
        name = m.group(1)
        if f"__{name}__" in self.outputs:
            # Resolved to $<label> once every node exists (see _resolve_outputs).
            return f"\x00{name}\x00"
        var = self.variables.get(f"__{name}__") or {}
        if var.get("constant") and not var.get("external") and "value" in var:
            return str(var["value"])
        return f"$exec.{name}"

    def _value(self, value: Any) -> str:
        """CACAO variables and our {{template}} slots -> Shuffle execution argument."""
        if not isinstance(value, str):
            value = json.dumps(value)
        value = _CACAO_VAR.sub(self._variable, value)
        return _TEMPLATE_VAR.sub(lambda m: f"$exec.{m.group(1)}", value)

    def _label(self, name: str) -> str:
        base = re.sub(r"[^A-Za-z0-9_]+", "_", name).strip("_") or "step"
        label, n = base, 1
        while label in self.labels:
            n += 1
            label = f"{base}_{n}"
        self.labels.add(label)
        return label

    # -- nodes ----------------------------------------------------------------

    def _node(self, node_id: str, name: str, app: Tuple[str, str], action: str,
              params: Dict[str, Any], description: str = "") -> Dict:
        entry = self.catalog.get(app, {})
        templates = entry.get("action_templates", {})
        template = templates.get(action)
        if not entry:
            self.warnings.append(f"{name}: app {app[0]} {app[1]} is not in the catalog")
        elif not template:
            self.warnings.append(f"{name}: {app[0]} {app[1]} has no action '{action}' "
                                 f"(it has: {', '.join(sorted(templates)[:12])})")
        else:
            known = {prm["name"] for prm in template.get("parameters") or []}
            for k in params:
                if k not in known:
                    self.warnings.append(f"{name}: '{action}' has no parameter '{k}'")
            for prm in template.get("parameters") or []:
                if (prm.get("required") and not prm.get("configuration")
                        and not params.get(prm["name"]) and not prm.get("value")
                        # reported once per machine by _ssh_params, for the operator to fill
                        and not (action == "run_ssh_command" and prm["name"] == "user_name")):
                    self.warnings.append(f"{name}: required parameter '{prm['name']}' "
                                         f"of '{action}' is empty")
        app_id = entry.get("app_id", "")
        if entry and not app_id:
            self.warnings.append(
                f"{name}: app_id of {app[0]} {app[1]} unknown (not in an export); "
                f"re-select the app on this node in the Shuffle editor if it won't run")
        node = copy.deepcopy(template) if template else {
            "app_name": app[0],
            "app_version": app[1],
            "name": action,
            "description": "",
            "environment": "Shuffle",
            "type": "ACTION",
            "is_valid": True,
            "isValid": True,
            "sharing": True,
            "public": True,
            "large_image": (entry.get("action_images", {}).get(action)
                            or entry.get("large_image", "")),
        }
        node.update({
            "id": node_id,
            "_id": node_id,
            "app_id": app_id,
            "label": self._label(name),
            "isStartNode": False,
            "position": {"x": 0.0, "y": 0.0},
            "parameters": self._parameters(app[0], action, params, node.get("parameters")),
        })
        if description:
            node["description"] = description
        if not node.get("large_image"):
            node["large_image"] = (entry.get("action_images", {}).get(action)
                                   or entry.get("large_image", ""))
        self.actions.append(node)
        return node

    def _parameters(self, app_name: str, action: str, params: Dict[str, Any],
                    template: Optional[List[Dict]] = None) -> List[Dict]:
        if template:
            out = [{**prm, "value": self._value(params.get(prm["name"], prm.get("value", "")))}
                   for prm in template]
            known = {prm["name"] for prm in template}
            return out + [{"name": k, "value": self._value(v), "multiline": True,
                           "required": False, "schema": {"type": "string"}}
                          for k, v in params.items() if k not in known]
        spec = ACTION_PARAMS.get((app_name, action), {})
        names = list(spec) + [k for k in params if k not in spec]
        return [{"name": k, "value": self._value(params.get(k, "")), "multiline": True,
                 "required": spec.get(k, False), "schema": {"type": "string"}}
                for k in names]

    @staticmethod
    def _shown(text: str) -> str:
        """For dry-run echoes: an unfilled {{name}} would become $exec.name, which Shuffle
        resolves to nothing; say plainly that the value is not set instead."""
        return _TEMPLATE_VAR.sub(lambda m: f"({m.group(1)} not set)", text)

    def _bash_node(self, node_id: str, name: str, commands: List[Dict], description: str,
                   step: Optional[Dict] = None) -> Dict:
        script = "\n".join(_command_text(c) for c in commands)
        if self.dry_run:
            return self._node(node_id, name, TOOLS_APP, "repeat_back_to_me",
                              {"call": self._shown(f"[bash, dry run] {script}")}, description)
        ssh = self._ssh_params(step or {})
        if ssh:
            return self._node(node_id, name, TOOLS_APP, "run_ssh_command",
                              {**{k: v for k, v in ssh.items() if v}, "command": script},
                              description)
        return self._node(node_id, name, TOOLS_APP, "execute_bash",
                          {"code": script}, description)

    def _machine(self, step: Dict, types: Tuple[str, ...],
                 targets_first: bool = False) -> Optional[Dict]:
        """The step's agent or first target whose CACAO type is one of `types`."""
        refs = [step.get("agent")] + list(step.get("targets") or [])
        if targets_first:  # http-api: the agent makes the call, the target is the API
            refs = refs[1:] + refs[:1]
        for ref in refs:
            d = self.definitions.get(ref or "")
            if d and d.get("type") in types:
                return d
        return None

    @staticmethod
    def _address(d: Dict) -> str:
        addr = d.get("address") or {}
        for kind in ("url", "dname", "ipv4", "ipv6", "domain"):
            if addr.get(kind):
                return addr[kind][0]
        return ""

    _LOOPBACK = ("127.0.0.1", "localhost", "::1")

    def _ssh_params(self, step: Dict) -> Optional[Dict[str, str]]:
        """Run ssh command parameters for the machine the step acts on, or None to run it
        in Shuffle's Tools app (execute_bash).

        The step's targets are looked at before its agent: the target is the machine acted
        on (the victim), the agent the system that executes the step. A loopback address
        means "where the playbook runs", i.e. Shuffle itself. Credentials come from the
        machine's CACAO authentication_info, else ssh_defaults, else stay empty for the
        operator to fill in Shuffle (one warning per machine).
        """
        machine = None
        for ref in list(step.get("targets") or []) + [step.get("agent")]:
            d = self.definitions.get(ref or "")
            if d and d.get("type") in ("ssh", "linux") and self._address(d) not in self._LOOPBACK:
                machine = d
                break
        if machine is None:
            if not self.ssh_defaults.get("host"):
                return None
            machine = {"name": "default ssh host"}
        auth = self.auth_infos.get(machine.get("authentication_info") or "", {})
        params = {"host": self._address(machine), "port": str(machine.get("port", "") or ""),
                  "user_name": auth.get("user_id") or auth.get("username") or "",
                  "password": auth.get("password", "")}
        # Key material in a key store (CACAO kms): for Shuffle, the id of the private key
        # file uploaded to Shuffle's Files (the run ssh command node's private_key_file_id)
        if auth.get("kms") and auth.get("kms_key_identifier"):
            params["private_key_file_id"] = auth["kms_key_identifier"]
            params["password"] = ""
        for k, v in self.ssh_defaults.items():
            if not params.get(k):
                params[k] = v
        if not params["host"]:
            self.warnings.append(f"{step.get('name', 'step')}: no ssh host for the machine this "
                                 f"step acts on; set its address in the CACAO target")
        if not (params["user_name"] and (params["password"] or params.get("private_key_file_id"))):
            label = machine.get("name") or params["host"]
            if label not in self._creds_warned:
                self._creds_warned.add(label)
                self.warnings.append(f"SSH credentials of '{label}' are left empty: fill User name "
                                     f"and Private key file id (or Password) on its Run ssh command "
                                     f"node(s) in Shuffle")
        return params

    def _http_auth(self, target: Optional[Dict]) -> Tuple[Dict[str, str], str]:
        """http app username/password, or an Authorization header, from the target's
        CACAO authentication_info (http-basic, user-auth, oauth2)."""
        auth = self.auth_infos.get((target or {}).get("authentication_info") or "", {})
        kind = auth.get("type", "")
        if kind in ("http-basic", "user-auth"):
            return {"username": auth.get("user_id") or auth.get("username") or "",
                    "password": auth.get("password", "")}, ""
        if kind == "oauth2" and auth.get("token"):
            return {}, f"{auth.get('oauth_header') or 'Authorization'}: Bearer {auth['token']}\n"
        return {}, ""

    def _http_node(self, node_id: str, name: str, command: Dict, description: str,
                   step: Dict, default_headers: Dict[str, str]) -> Dict:
        """http-api / openc2-http: the http app action named by the HTTP method."""
        text = _command_text(command)
        method, _, rest = text.partition(" ")
        path = rest.split(" ")[0] if rest else method
        hdrs = {**default_headers, **{k: (v[0] if isinstance(v, list) else v)
                                      for k, v in (command.get("headers") or {}).items() if v}}
        target = self._machine(step, ("http-api",), targets_first=True)
        base = self._address(target) if target else ""
        if base and not path.startswith("http"):
            # A placeholder ({{incident_api_url}}) is a whole base URL, scheme included
            if "://" not in base and "{{" not in base and "$" not in base:
                scheme = "https" if str(target.get("port", "443")) == "443" else "http"
                port = target.get("port")
                base = f"{scheme}://{base}" + (f":{port}" if port not in (None, "", "80", "443") else "")
            path = base.rstrip("/") + "/" + path.lstrip("/")
        auth_params, auth_header = self._http_auth(target)
        params = {"url": path, "headers": "".join(f"{k}: {v}\n" for k, v in hdrs.items()) + auth_header,
                  **{k: v for k, v in auth_params.items() if v}}
        body = _content_text(command)
        if body:
            params["body"] = body
        elif command.get("content_b64"):
            self.warnings.append(f"{name}: binary content_b64 cannot be an http body; left out")
        unset = _TEMPLATE_VAR.findall(path)
        if unset:
            self.warnings.append(f"{name}: the API address {{{{{unset[0]}}}}} is not set (for the "
                                 f"library playbooks: {unset[0].upper()} in .env); the http node "
                                 f"has no host until it is")
        elif not path.startswith("http") and "$" not in path:
            self.warnings.append(f"{name}: http-api url is the bare path '{path}'; "
                                 f"give the step an http-api target or set the host in Shuffle")
        action = method.upper() if rest else "GET"
        if action not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            self.warnings.append(f"{name}: HTTP method '{method}' is not an action of the http app")
        return self._node(node_id, name, HTTP_APP, action, params, description)

    def _command_node(self, node_id: str, name: str, command: Dict, description: str,
                      step: Optional[Dict] = None) -> Dict:
        """One CACAO command (other than bash, see _bash_node) -> one Shuffle node."""
        step = step or {}
        ctype = command.get("type", "")
        text = _command_text(command)
        if self.dry_run and ctype in ("http-api", "openc2-http", "ssh", "powershell"):
            target = self._machine(step, ("http-api", "ssh", "linux"), targets_first=True)
            where = self._address(target) if target else ""
            body = _content_text(command)
            return self._node(node_id, name, TOOLS_APP, "repeat_back_to_me",
                              {"call": self._shown(f"[{ctype}, dry run] {text} -> {where}"
                                                   + (f" {body}" if body else ""))}, description)
        if ctype == "http-api":
            return self._http_node(node_id, name, command, description, step, {})
        if ctype == "openc2-http":
            # OpenC2 over HTTPS: a POST of the OpenC2 command (JSON) to the actuator
            return self._http_node(node_id, name, command, description, step,
                                   {"Content-Type": "application/openc2-cmd+json;version=1.0"})
        if ctype in ("ssh", "powershell"):
            ssh = self._ssh_params(step)
            if ssh and ssh.get("host"):
                if ctype == "powershell":
                    # -EncodedCommand (UTF-16LE base64) survives any quoting in the script
                    enc = base64.b64encode(text.encode("utf-16-le")).decode()
                    text = f"powershell -NoProfile -NonInteractive -EncodedCommand {enc}"
                return self._node(node_id, name, TOOLS_APP, "run_ssh_command",
                                  {**{k: v for k, v in ssh.items() if v}, "command": text},
                                  description)
            if ctype == "ssh":   # no remote machine: the command runs in Shuffle's Tools app
                self.warnings.append(f"{name}: ssh command without an ssh/linux target with an "
                                     f"address; it runs as execute_bash in Shuffle's Tools app")
                return self._node(node_id, name, TOOLS_APP, "execute_bash", {"code": text}, description)
            self.warnings.append(f"{name}: powershell needs an ssh target (a Windows host with "
                                 f"OpenSSH); Shuffle's Tools app has no PowerShell. Emitted as an echo")
            return self._node(node_id, name, TOOLS_APP, "repeat_back_to_me",
                              {"call": f"[powershell] {text}"}, description)
        if ctype == "manual":
            self.warnings.append(f"{name}: manual step shown to the analyst; Shuffle does not pause "
                                 f"for it (add a User Input trigger in the editor to wait for a decision)")
            return self._node(node_id, name, TOOLS_APP, "repeat_back_to_me",
                              {"call": f"[manual] {text}"}, description)
        self.warnings.append(f"{name}: '{ctype}' command has no Shuffle app; emitted as an echo "
                             f"for an analyst to rebind")
        return self._node(node_id, name, TOOLS_APP, "repeat_back_to_me",
                          {"call": f"[{ctype}] {text}"}, description)

    def _step(self, step_id: str, step: Dict) -> None:
        stype = step.get("type")
        name = step.get("name") or stype or _uuid_part(step_id)
        desc = step.get("description", "")
        first_id = _node_id(step_id)

        binding = (step.get("step_extensions") or {}).get(SHUFFLE_EXTENSION_ID)
        # An extension with only "outputs" maps output paths for a step converted as usual
        if binding and binding.get("app_name"):
            app = (binding["app_name"], binding["app_version"])
            self._node(first_id, name, app, binding["action"],
                       binding.get("parameters") or {}, desc)
            self.span[step_id] = (first_id, first_id)
            return

        # "single" is the CACAO 1.x name of an action step; read it the same way
        if stype in ("action", "single") and step.get("commands"):
            # Consecutive bash commands share one execute_bash node, as a script.
            groups: List[List[Dict]] = []
            for cmd in step["commands"]:
                if cmd.get("type") == "bash" and groups and groups[-1][0].get("type") == "bash":
                    groups[-1].append(cmd)
                else:
                    groups.append([cmd])
            ids = [first_id] + [_derived_id(step_id, str(i)) for i in range(1, len(groups))]
            for i, (nid, group) in enumerate(zip(ids, groups)):
                label = name if len(ids) == 1 else f"{i + 1}-{name}"
                if group[0].get("type") == "bash":
                    self._bash_node(nid, label, group, desc, step)
                else:
                    self._command_node(nid, label, group[0], desc, step)
            for a, b in zip(ids, ids[1:]):
                self._branch(a, b)
            self.span[step_id] = (ids[0], ids[-1])
            return

        if step.get("commands"):
            self.warnings.append(f"{name}: {len(step['commands'])} command(s) of a '{stype}' step "
                                 f"are not converted (only action steps carry commands)")
        # Control-flow steps become a pass-through node; their logic goes on its outgoing
        # branches as Shuffle conditions (see _routing).
        if stype in ("if-condition", "switch-condition"):
            self.routes[step_id] = self._routing(name, step)
            parsed, _ = (parse_condition(step.get("condition", "")) if stype == "if-condition"
                         else (None, ""))
            # The node's output shows the value its branches test ("Flagged?: 5"); the
            # comparison itself is on the outgoing branches
            call = (f"{name}: " + ", ".join(self._value(lhs) for lhs, _, _, _ in parsed) if parsed
                    else f"[if] {step.get('condition', '')}" if stype == "if-condition"
                    else f"{name}: {self._value(step.get('switch', ''))}")
        elif stype == "while-condition":
            self.warnings.append(f"{name}: while-condition '{step.get('condition')}' is not "
                                 f"translated (Shuffle workflows have no loops); its body runs once")
            call = f"[while] {step.get('condition', '')}"
        elif stype == "parallel":
            call = f"[parallel] {len(step.get('next_steps') or [])} branches"
        elif stype == "playbook-action":
            self.warnings.append(f"{name}: playbook-action '{step.get('playbook_id')}' "
                                 f"should become a Shuffle subflow; emitted as an echo")
            call = f"[playbook-action] {step.get('playbook_id', '')}"
        else:
            call = f"[{stype}] {name}"
        self._node(first_id, name, TOOLS_APP, "repeat_back_to_me", {"call": call}, desc)
        self.span[step_id] = (first_id, first_id)

    # -- edges ----------------------------------------------------------------

    def _routing(self, name: str, step: Dict) -> Dict[str, List[Dict]]:
        """Shuffle conditions for each outgoing branch of an if- or switch-condition step;
        a successor without an entry gets an unconditional branch."""
        if step.get("type") == "switch-condition":
            source = self._value(step.get("switch", ""))
            cases = step.get("cases") or {}
            values = [str(v) for v in cases if str(v) != "default"]
            out = {}
            for value, nxt in cases.items():
                if str(value) == "default":   # none of the other cases: AND of "does not equal"
                    out[nxt] = [self._condition(source, "does not equal", v) for v in values]
                else:
                    out[nxt] = [self._condition(source, "equals", str(value))]
            return out
        parsed, why = parse_condition(step.get("condition", ""))
        on_true, on_false = step.get("on_true"), step.get("on_false")
        if parsed is None or (len(parsed) > 1 and on_false):
            why = why or "the negation of several ANDed comparisons is an OR"
            self.warnings.append(f"{name}: condition '{step.get('condition')}' not translated "
                                 f"({why}); both outcome branches will run")
            return {}
        if any(op == "contains_any_of" for _, op, _, _ in parsed):
            self.warnings.append(f"{name}: IN is approximated by Shuffle's contains_any_of "
                                 f"(substring match)")
        out = {}
        if on_true:
            out[on_true] = [self._condition(self._value(lhs), op, value, neg)
                            for lhs, op, value, neg in parsed]
        if on_false:
            lhs, op, value, neg = parsed[0]
            out[on_false] = [self._condition(self._value(lhs), op, value, not neg)]
        return out

    def _branch(self, src: str, dst: str, conditions: Optional[List[Dict]] = None) -> None:
        if any(b["source_id"] == src and b["destination_id"] == dst for b in self.branches):
            return
        self.branches.append({
            "id": _derived_id(src, dst),
            "source_id": src,
            "destination_id": dst,
            "label": "",
            "has_errors": False,
            "conditions": conditions or [],
            "decorator": False,
            "parent_controlled": False,
            "source_parent": "",
        })

    @staticmethod
    def _condition(source: str, op: str, destination: str, negate: bool = False) -> Dict:
        """One Shuffle branch condition, as the editor and shuffle-shared createCondition()
        build it. The app SDK follows a branch only if all its conditions hold, and
        inverts one whose "condition" parameter has configuration=true (the editor's NOT)."""
        cid = _derived_id(source, op, destination, str(negate))
        return {
            "source": {"id": cid, "name": "source", "variant": "STATIC_VALUE", "value": source},
            "condition": {"id": cid, "name": "condition", "value": op, "configuration": negate},
            "destination": {"id": cid, "name": "destination", "variant": "STATIC_VALUE",
                            "value": destination},
        }

    @staticmethod
    def _successors(step: Dict) -> List[str]:
        out = [step.get(k) for k in ("on_completion", "on_success", "on_true", "on_false")]
        out += step.get("next_steps") or []
        out += list((step.get("cases") or {}).values())
        return [s for s in out if s]

    # -- whole playbook -------------------------------------------------------

    def _shuffle_start(self) -> str:
        ws = self.cacao.get("workflow_start")
        start = self.workflow.get(ws)
        if not start:
            raise ConversionError(f"workflow_start '{ws}' is not a step")
        if start.get("type") != "start" or start.get("commands"):
            return ws
        first = start.get("on_completion") or start.get("on_success")
        if not first or first not in self.workflow or self.workflow[first].get("type") == "end":
            raise ConversionError("the start step leads to no executable step")
        return first

    def _layout(self, start: str) -> None:
        nexts: Dict[str, List[str]] = {}
        for b in self.branches:
            nexts.setdefault(b["source_id"], []).append(b["destination_id"])
        depth, queue = {start: 0}, deque([start])
        while queue:
            n = queue.popleft()
            for m in nexts.get(n, []):
                if m not in depth:
                    depth[m] = depth[n] + 1
                    queue.append(m)
        rows: Dict[int, int] = {}
        for a in self.actions:
            d = depth.get(a["id"], max(depth.values(), default=0) + 1)
            col = rows.get(d, 0)
            rows[d] = col + 1
            a["position"] = {"x": _X0 + col * _DX, "y": _Y0 + d * _DY}
        # Flow order, start node first, as the Shuffle editor exports them.
        self.actions.sort(key=lambda a: (a["position"]["y"], a["position"]["x"]))

    def _resolve_outputs(self) -> None:
        label_of = {a["id"]: a["label"] for a in self.actions}
        refs = {}
        for var, (sid, path) in self.outputs.items():
            name = var.strip("_")
            if sid in self.span:
                ref = "$" + label_of[self.span[sid][1]].lower()
                refs[name] = f"{ref}.{path}" if path else ref
            else:
                refs[name] = f"$exec.{name}"
        fields = [prm for a in self.actions for prm in a["parameters"]]
        fields += [c[k] for b in self.branches for c in b["conditions"] for k in ("source", "destination")]
        for prm in fields:
            if "\x00" in prm.get("value", ""):
                prm["value"] = re.sub(r"\x00(\w+?)\x00",
                                      lambda m: refs.get(m.group(1), m.group(0)), prm["value"])

    def convert(self) -> Dict:
        if not self.workflow:
            raise ConversionError("playbook has no workflow")
        start_step = self._shuffle_start()

        for step_id in sorted(self.workflow):
            step = self.workflow[step_id] or {}
            if step.get("type") in ("start", "end") and not step.get("commands"):
                continue
            self._step(step_id, step)

        for step_id in sorted(self.span):
            step = self.workflow[step_id]
            # Only a loss when failure leads somewhere success does not (most library
            # steps send both to the same next step)
            if step.get("on_failure") and step["on_failure"] not in self._successors(step):
                self.warnings.append(
                    f"{step.get('name', step_id)}: on_failure -> {step['on_failure']} dropped; "
                    f"Shuffle branches only fire on success")
            for nxt in self._successors(step):
                if nxt in self.span:
                    self._branch(self.span[step_id][1], self.span[nxt][0],
                                 (self.routes.get(step_id) or {}).get(nxt))
                elif nxt not in self.workflow:
                    self.warnings.append(f"{step_id} links to unknown step {nxt}")

        self._resolve_outputs()
        start_id = self.span[start_step][0]
        for a in self.actions:
            a["isStartNode"] = a["id"] == start_id
        self._layout(start_id)

        return {
            # Changes with the content: re-importing an updated conversion must not be
            # mistaken by Shuffle for the workflow imported last time.
            "id": _derived_id(self.cacao.get("id", ""), json.dumps(
                [self.actions, self.branches], sort_keys=True)),
            "name": self.cacao.get("name", "CACAO playbook"),
            "description": self.cacao.get("description", ""),
            "tags": [str(t) for t in self.cacao.get("labels") or []      # CACAO labels
                     if "<fill" not in str(t)],
            "start": start_id,
            "actions": self.actions,
            "branches": self.branches,
            "triggers": [],
            "visual_branches": [],
            "comments": [],
            "workflow_variables": None,
            "configuration": {"exit_on_error": False, "start_from_top": False,
                              "skip_notifications": False},
            "is_valid": True,
            "isValid": True,
            "previously_saved": False,
        }


def convert(cacao: Dict, catalog: Optional[Catalog] = None, dry_run: bool = False,
            ssh_defaults: Optional[Dict[str, str]] = None) -> Tuple[Dict, List[str]]:
    """Return (shuffle_workflow, warnings). Raises ConversionError if impossible."""
    conv = _Converter(cacao, _merge(load_full_catalog(), catalog or {}), dry_run, ssh_defaults)
    workflow = conv.convert()
    for w in conv.warnings:
        logger.info("cacao_to_shuffle: %s", w)
    return workflow, conv.warnings


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("cacao", nargs="?", help="CACAO 2.0 playbook (JSON, or a playbooks/*.yaml template)")
    ap.add_argument("-o", "--out", help="output Shuffle workflow JSON (default: stdout)")
    ap.add_argument("--live-catalog", action="store_true",
                    help="resolve app ids from the Shuffle instance in .env")
    ap.add_argument("--dry-run", action="store_true",
                    help="echo bash commands instead of running them (execute_bash)")
    ap.add_argument("--learn-from", metavar="EXPORT", action="append", default=[],
                    help="add app ids and icons from a Shuffle workflow export to "
                         f"{CATALOG_PATH.name}; repeatable")
    ap.add_argument("--sync-python-apps", nargs="?", const="", metavar="CHECKOUT",
                    help=f"rebuild {PYTHON_APPS_PATH.name} from {PYTHON_APPS_REPO} "
                         "(fetched, or a local checkout)")
    args = ap.parse_args()

    if args.sync_python_apps is not None:
        apps = sync_python_apps(Path(args.sync_python_apps) if args.sync_python_apps else None)
        n = sum(len(a["action_templates"]) for a in apps.values())
        print(f"{PYTHON_APPS_PATH}: {len(apps)} app(s), {n} action(s)",
              file=__import__("sys").stderr)
    if args.learn_from:
        catalog = load_catalog()
        for path in args.learn_from:
            with open(path) as f:
                learn_catalog(json.load(f), catalog)
        save_catalog(catalog)
        print(f"{CATALOG_PATH}: {len(catalog)} app(s)", file=__import__("sys").stderr)
    if not args.cacao:
        return

    import yaml  # JSON is YAML, so this also reads plain CACAO JSON

    with open(args.cacao) as f:
        cacao = yaml.safe_load(f)
    cacao = cacao.get("cacao", cacao)  # library templates wrap the playbook (playbooks/*.yaml)
    workflow, warnings = convert(cacao, fetch_app_catalog() if args.live_catalog else None,
                                 dry_run=args.dry_run)
    text = json.dumps(workflow, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
    else:
        print(text)
    for w in warnings:
        print(f"warning: {w}", file=__import__("sys").stderr)


if __name__ == "__main__":
    main()
