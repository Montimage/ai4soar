"""
One-time script to seed the MITRE ATT&CK knowledge base into MongoDB.

Run from the ai4soar project root:
    python scripts/seed_mitre_kb.py

This populates the `mitre_kb` collection so the recommendation service can
query MongoDB instead of re-parsing the 49 MB STIX JSON on every restart.
"""

import sys
import os
import logging

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymongo import MongoClient, ASCENDING
from pymongo.errors import BulkWriteError
from core.config import config
from core.intelligent_orchestration.stix_knowledge_base import STIXKnowledgeBase

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)


def seed():
    logger.info("=== AI4SOAR MITRE KB Seeder ===")

    # Load knowledge base from STIX JSON
    kb = STIXKnowledgeBase(config.stix.data_path)
    kb.load()
    stats = kb.stats()
    logger.info(f"STIX loaded: {stats}")

    # Connect to MongoDB
    client = MongoClient(config.mongodb.host, config.mongodb.port)
    db = client[config.mongodb.database]
    collection = db[config.mongodb.mitre_kb_collection]

    # Drop existing data so we can re-seed cleanly
    existing = collection.count_documents({})
    if existing:
        logger.info(f"Dropping {existing} existing documents from {config.mongodb.mitre_kb_collection}")
        collection.drop()

    # Build documents
    docs = []
    for tech_id, tech_info in kb._techniques.items():
        mitigations = kb.get_playbooks_for_technique(tech_id)
        docs.append({
            "_id": tech_id,
            "technique_id": tech_id,
            "technique_name": tech_info["name"],
            "tactics": tech_info["tactics"],
            "platforms": tech_info["platforms"],
            "is_subtechnique": tech_info["is_subtechnique"],
            "description": tech_info["description"][:500] if tech_info["description"] else "",
            "playbooks": mitigations,
            "playbook_count": len(mitigations),
        })

    logger.info(f"Inserting {len(docs)} technique documents …")
    try:
        result = collection.insert_many(docs, ordered=False)
        logger.info(f"Inserted {len(result.inserted_ids)} documents")
    except BulkWriteError as e:
        logger.warning(f"Bulk write partial error (duplicates skipped): {e.details['nInserted']} inserted")

    # Create index for fast technique_id lookups
    collection.create_index([("technique_id", ASCENDING)], unique=True)
    logger.info("Created index on technique_id")

    # Summary
    final_count = collection.count_documents({})
    with_playbooks = collection.count_documents({"playbook_count": {"$gt": 0}})
    logger.info(f"=== Seeding complete ===")
    logger.info(f"  Total techniques in DB : {final_count}")
    logger.info(f"  With playbooks         : {with_playbooks}")
    logger.info(f"  Without playbooks      : {final_count - with_playbooks}")

    client.close()


if __name__ == "__main__":
    seed()
