"""
STIX 2.1 bundle builder for AI4SOAR alert responses.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict


class STIXBuilder:
    """Builds STIX 2.1 bundles wrapping AI4SOAR alert responses."""

    def build_stix_bundle(
        self,
        scenario: str,
        response_body: Dict[str, Any],
        triaged_alert: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Wrap a SOAR response into a minimal STIX 2.1 bundle for Kafka publishing.

        Args:
            scenario:      Scenario identifier (e.g. "sc1")
            response_body: Action details from the recommendation engine
            triaged_alert: The original alert that was triaged

        Returns:
            STIX 2.1 bundle dict ready for serialization.
        """
        now = datetime.now(timezone.utc).isoformat()
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "created": now,
            "objects": [
                {
                    "type": "course-of-action",
                    "id": f"course-of-action--{uuid.uuid4()}",
                    "spec_version": "2.1",
                    "created": now,
                    "modified": now,
                    "name": response_body.get("playbook", "Unknown Playbook"),
                    "description": response_body.get("description", ""),
                    "x_ai4soar_scenario": scenario,
                    "x_ai4soar_alert_id": triaged_alert.get("_id", ""),
                    "x_ai4soar_response": response_body,
                }
            ],
        }
