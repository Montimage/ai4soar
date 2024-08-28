import requests
import json
import time
from requests.auth import HTTPBasicAuth

# Wazuh server details
wazuh_server = 'https://192.168.21.35:9200'

# Authentication credentials
username = 'admin'
password = 'SecretPassword'

# API endpoint for fetching alerts
endpoint = '/wazuh-alerts-*/_search'

# Headers for the request
headers = {
    'Content-Type': 'application/json'
}

# Query parameters for fetching the most recent alerts
query_params_recent = {
    "size": 10,  # Number of alerts to fetch
    "sort": [{
        "@timestamp": {
            "order": "desc"
        }
    }]
}

# Query parameters for fetching the most recent alerts with specific characteristics
query_params = {
    "size": 1,
    "sort": [{
        "@timestamp": {
            "order": "desc"
        }
    }],
    "query": {
        "bool": {
            "must": [
                {"match": {"agent.ip": "192.168.21.231"}},
                {"match": {"predecoder.program_name": "sshd"}},
                {"match": {"rule.groups": "sshd"}},
                #{"match": {"@timestamp": "2024-08-02T08:49:14.522+0000"}}
            ]
        }
    }
}

def fetch_alerts():
    # Make the request to the Wazuh API with basic authentication
    response = requests.get(
        wazuh_server + endpoint,
        headers=headers,
        json=query_params,
        auth=(username, password),
        verify=False  # Disable SSL certificate verification
    )

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the JSON response
        alerts = response.json()
        #print("Retrieve alerts from Wazuh's server")
        print(json.dumps(alerts, indent=4))
        return alerts
    else:
        print(f"Failed to retrieve alerts: {response.status_code}")
        print(response.text)
        return None

"""
while True:
    fetch_alerts()
    print("Wait for 30 seconds before the next query")
    time.sleep(30)
"""
fetch_alerts()
