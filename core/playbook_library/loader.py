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
from typing import Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


class PlaybookLibrary:

    def __init__(self, library_path: str) -> None:
        self._path = library_path
        self._by_technique: Dict[str, List[Dict]] = {}
        self._by_tactic:    Dict[str, List[Dict]] = {}
        self._loaded = False
        self._signature: Optional[Tuple] = None

    def _dir_signature(self) -> Tuple:
        """(filename, mtime, size) for every template, as a cheap change detector.

        The orchestrator holds one PlaybookLibrary for the process lifetime, so without
        this an edited YAML file would keep serving the old template until a restart —
        while the Playbooks page, which re-globs per request, already showed the new one.
        Catches edits, additions and deletions; 17 stat() calls per recommendation is
        not measurable next to an LLM round-trip.
        """
        try:
            names = sorted(
                f for f in os.listdir(self._path) if f.endswith((".yaml", ".yml"))
            )
        except OSError:
            return ()
        sig = []
        for name in names:
            try:
                st = os.stat(os.path.join(self._path, name))
                sig.append((name, st.st_mtime_ns, st.st_size))
            except OSError:
                continue
        return tuple(sig)

    def load(self, force: bool = False) -> None:
        """Parse all YAML files in the library directory.

        Re-parses only when a template file has changed on disk (or force=True), so
        repeated calls on an unchanged directory cost one listdir plus a stat per file.
        """
        if not os.path.isdir(self._path):
            if not self._loaded:
                logger.warning(f"[PlaybookLibrary] Directory not found: {self._path}")
            self._loaded = True
            return

        signature = self._dir_signature()
        if self._loaded and not force and signature == self._signature:
            return

        if self._loaded:
            logger.info("[PlaybookLibrary] Templates changed on disk — reloading")
        # Rebuild from scratch: an in-place update would leave entries for techniques a
        # template no longer claims, or for files that were deleted.
        self._by_technique = {}
        self._by_tactic    = {}
        self._signature    = signature

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
