"""
PlaybookLibrary — loads CACAO YAML templates and indexes them by technique / tactic.

Each YAML file declares:
  techniques: [T1110, T1110.001, ...]
  tactics:    [credential-access, ...]
  parameters: { param_name: {type, required, sources, default, description} }
  cacao:      full CACAO 2.0 playbook template with {{variable}} placeholders
"""

import logging
import os
from typing import Dict, List

import yaml

logger = logging.getLogger(__name__)


class PlaybookLibrary:

    def __init__(self, library_path: str) -> None:
        self._path = library_path
        self._by_technique: Dict[str, List[Dict]] = {}
        self._by_tactic:    Dict[str, List[Dict]] = {}
        self._loaded = False

    def load(self) -> None:
        """Parse all YAML files in the library directory. Idempotent."""
        if self._loaded:
            return

        if not os.path.isdir(self._path):
            logger.warning(f"[PlaybookLibrary] Directory not found: {self._path}")
            self._loaded = True
            return

        count = 0
        for fname in sorted(os.listdir(self._path)):
            if not fname.endswith((".yaml", ".yml")):
                continue
            fpath = os.path.join(self._path, fname)
            try:
                with open(fpath, encoding="utf-8") as f:
                    template = yaml.safe_load(f)
                if not isinstance(template, dict) or "id" not in template:
                    logger.warning(f"[PlaybookLibrary] Skipping invalid template: {fname}")
                    continue
                for tid in template.get("techniques", []):
                    self._by_technique.setdefault(tid, []).append(template)
                for tactic in template.get("tactics", []):
                    self._by_tactic.setdefault(tactic, []).append(template)
                count += 1
                logger.debug(f"[PlaybookLibrary] Loaded {fname} → techniques={template.get('techniques', [])}")
            except Exception as exc:
                logger.error(f"[PlaybookLibrary] Failed to load {fname}: {exc}")

        logger.info(
            f"[PlaybookLibrary] {count} templates loaded: "
            f"{len(self._by_technique)} technique keys, "
            f"{len(self._by_tactic)} tactic keys"
        )
        self._loaded = True

    def get_for_technique(self, technique_id: str) -> List[Dict]:
        """
        Return templates that cover the given technique ID.
        Falls back to the parent technique (T1110.001 → T1110) if no exact match.
        """
        self.load()
        seen: set = set()
        results: List[Dict] = []
        for t in self._by_technique.get(technique_id, []):
            if t["id"] not in seen:
                seen.add(t["id"])
                results.append(t)
        # parent fallback: T1110.001 → T1110
        parent = technique_id.split(".")[0]
        if parent != technique_id:
            for t in self._by_technique.get(parent, []):
                if t["id"] not in seen:
                    seen.add(t["id"])
                    results.append(t)
        return results

    def get_for_tactic(self, tactic: str) -> List[Dict]:
        """Return all templates tagged with the given tactic phase_name."""
        self.load()
        return list(self._by_tactic.get(tactic, []))

    def stats(self) -> Dict:
        self.load()
        all_ids = {t["id"] for ts in self._by_technique.values() for t in ts}
        return {
            "total_templates": len(all_ids),
            "techniques_covered": len(self._by_technique),
            "tactics_covered": len(self._by_tactic),
        }
