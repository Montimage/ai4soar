# CACAO 2.0 JSON Schemas (vendored)

Official OASIS JSON schemas for CACAO Security Playbooks v2.0, used by
`core/playbook_verification` and `scripts/path_d_metrics.py` to validate generated
playbooks against the standard rather than against our own checker.

- Source: https://github.com/oasis-open/cacao-json-schemas  (OASIS TC Open Repository)
- Commit: 72853294a18b7d42af84fe1cc410ac70b1366c3b  (2024-01-23)
- Covers: CACAO 2.0 only (not 1.0 / 1.1)
- License: Apache-2.0 — see LICENSE in this directory

Vendored rather than fetched at runtime or added as a submodule: validation must work
offline and give byte-identical results for a given release, and 304 KB of JSON is
cheaper than a network dependency in the request path. `playbook.json` is the entry
point; the other 50 files are reached through `$ref` and must all be present.

To update: re-clone the repository, copy `schemas/` here, and record the new commit.
