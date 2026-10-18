"""
Save a library template edited in the UI (the Workflow view's Edit mode) back to its
YAML file in playbooks/.

Only the `cacao:` section is rewritten, and the version is bumped; everything above it
(id, techniques, parameters, ...) stays byte for byte as authored. Comments inside the
old `cacao:` section are not kept: the step descriptions are the place for that text.
"""

import copy
import glob
import os
import re
from typing import Dict, List

import yaml

from core.config import config
from core.intelligent_orchestration.parameterizer import AI4SOAR_IDENTITY, _to_spec_ids
from core.playbook_verification.schema import schema_errors


class TemplateEditError(ValueError):
    pass


class _Dumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)      # lists indented under their key


def _str(dumper, s: str):
    # Multi-line commands and descriptions as literal blocks, as the templates are written
    style = "|" if "\n" in s else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", s, style=style)


_Dumper.add_representer(str, _str)


def _template_path(template_id: str) -> str:
    for path in sorted(glob.glob(os.path.join(config.playbook_library.path, "*.y*ml"))):
        with open(path, encoding="utf-8") as fh:
            if (yaml.safe_load(fh) or {}).get("id") == template_id:
                return path
    raise TemplateEditError(f"no template with id '{template_id}'")


def _bump(version: str) -> str:
    parts = str(version or "1.0").split(".")
    try:
        parts[-1] = str(int(parts[-1]) + 1)
    except ValueError:
        parts.append("1")
    return ".".join(parts)


def structural_errors(cacao: Dict) -> List[str]:
    """Official-schema errors, ignoring values that still hold a {{parameter}}."""
    if not isinstance(cacao, dict) or not isinstance(cacao.get("workflow"), dict):
        return ["the playbook has no workflow"]
    if cacao.get("workflow_start") not in cacao["workflow"]:
        return ["workflow_start does not name a step of the workflow"]
    empty = [f"step '{s.get('name') or sid}' has no command" for sid, s in cacao["workflow"].items()
             if s.get("type") == "action"
             and not any((c.get("command") or c.get("command_b64") or "").strip()
                         for c in s.get("commands") or [])]
    return empty + [f"{e['path']}: {e['message']}" for e in schema_errors(cacao) or []
                    if not e["unfilled"]]


def save_template_cacao(template_id: str, cacao: Dict) -> Dict:
    """Write `cacao` as the template's new CACAO section. Returns {file, version}."""
    if not isinstance(cacao, dict):
        raise TemplateEditError("cannot save: the playbook is not a CACAO object")
    # Checked as it will be once filled for an alert: templates keep readable step keys
    # (step--block-ip) and no timestamps, which the parameterizer turns into spec form
    filled = _to_spec_ids(copy.deepcopy(cacao), template_id)
    filled.setdefault("created_by", AI4SOAR_IDENTITY)
    filled.setdefault("created", "2026-01-01T00:00:00Z")
    filled.setdefault("modified", "2026-01-01T00:00:00Z")
    errors = structural_errors(filled)
    if errors:
        raise TemplateEditError("cannot save: " + "; ".join(errors[:5]))
    path = _template_path(template_id)
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    head, sep, _ = text.partition("\ncacao:")
    if not sep:
        raise TemplateEditError(f"{os.path.basename(path)} has no top-level cacao: section")

    version = _bump((yaml.safe_load(text) or {}).get("version"))
    head, n = re.subn(r'(?m)^version:.*$', f'version: "{version}"', head, count=1)
    if not n:
        head = head.replace("\nname:", f'\nversion: "{version}"\nname:', 1)
    body = yaml.dump({"cacao": cacao}, Dumper=_Dumper, sort_keys=False,
                     allow_unicode=True, width=4096, indent=2)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(head + "\n" + body)
    return {"file": os.path.basename(path), "version": version}
