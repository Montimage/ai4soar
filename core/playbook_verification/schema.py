"""
Validation against the official OASIS CACAO 2.0 JSON schemas vendored in data/cacao-schemas/.
"""

import functools
import glob
import json
import logging
import os
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

SCHEMA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "cacao-schemas")
SCHEMA_DRAFT = "2020-12"


@functools.lru_cache(maxsize=1)
def schema_validator():
    """Draft 2020-12 validator for playbook.json with every $ref'd schema preregistered.

    Returns None (rather than raising) if the vendored schemas or a new enough jsonschema
    are absent; callers must report the check as unavailable, not as passed.
    """
    entry = os.path.join(SCHEMA_DIR, "playbook.json")
    if not os.path.exists(entry):
        return None
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012
    except ImportError:
        logger.warning("Official CACAO schema validation disabled: needs jsonschema>=4.18 and referencing")
        return None
    with open(entry, encoding="utf-8") as f:
        schema = json.load(f)
    resources = []
    for path in glob.glob(os.path.join(SCHEMA_DIR, "**", "*.json"), recursive=True):
        try:
            with open(path, encoding="utf-8") as f:
                sub = json.load(f)
        except Exception:
            continue
        if isinstance(sub, dict) and "$id" in sub:
            resources.append((sub["$id"], Resource(contents=sub, specification=DRAFT202012)))
    return Draft202012Validator(schema, registry=Registry().with_resources(resources))


def schema_errors(cacao: Dict) -> Optional[List[Dict]]:
    """Leaf-level schema errors as [{"path": "workflow/action--…", "message": "…"}].

    None when the validator is unavailable. Errors under anyOf/oneOf are flattened to
    their leaves: the top-level message ("… is not valid under any of the given schemas")
    says nothing about what to fix.
    """
    v = schema_validator()
    if v is None:
        return None
    out, seen = [], set()

    def leaves(err):
        if err.context:
            for sub in err.context:
                leaves(sub)
            return
        path = "/".join(str(p) for p in err.absolute_path) or "(root)"
        key = (path, err.message)
        if key not in seen:
            seen.add(key)
            # A value still holding a {{placeholder}} was not filled (missing alert field or
            # unset deployment setting): reported apart from real structural errors
            out.append({"path": path, "message": err.message,
                        "unfilled": isinstance(err.instance, str) and "{{" in err.instance})

    for err in v.iter_errors(cacao):
        leaves(err)
    return out
