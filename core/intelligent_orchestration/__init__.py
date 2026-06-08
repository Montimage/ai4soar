"""
Intelligent Orchestration module for AI4SOAR.

Components:
  - stix_knowledge_base  : MITRE ATT&CK STIX parser (Path A)
  - normalizer           : Format-agnostic alert normalization (Path B)
  - feature_engineer     : TF-IDF + structured feature extraction (Path B)
  - playbook_registry    : Tactic/mitigation → Shuffle playbook name mapping
"""
