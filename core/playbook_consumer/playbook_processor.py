import os
import json
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient('localhost', 27017)
# Access/Create the database "ai4soar"
db = client['ai4soar']
# Collection of alerts and playbooks
alerts_collection = db['alerts']
playbooks_collection = db['playbooks']

ALERTS_DIR = "../../tests/alerts"

# Iterate over each file in the alerts folder and insert them into the alerts's collection
for filename in os.listdir(ALERTS_DIR):
    if filename.endswith('.json'):
        file_path = os.path.join(ALERTS_DIR, filename)
        with open(file_path, 'r') as file:
            alert = json.load(file)
            alerts_collection.insert_one(alert)

# TODO: later we need to insert alerts received from Kafka channel into the alerts's collection