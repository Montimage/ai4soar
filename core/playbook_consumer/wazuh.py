import sys
import requests
import json
import time
from requests.auth import HTTPBasicAuth

# Wazuh server details
wazuh_servers = {
    'uc1': 'https://192.168.21.35:9200',
    'uc2': '',
    'uc3': 'https://192.168.56.50:9200'
}

# Authentication credentials
credentials = {
    'uc1': ('admin', 'SecretPassword'),
    'uc2': ('', ''),
    'uc3': ('admin', 'admin')
}

# API endpoint for fetching alerts
endpoint = '/wazuh-alerts-*/_search'

# Headers for the request
headers = {
    'Content-Type': 'application/json'
}

# TODO: Query parameters for fetching the most recent alerts
query_params_uc2 = {
    "size": 10,  # Number of alerts to fetch
    "sort": [{
        "@timestamp": {
            "order": "desc"
        }
    }]
}

# Query parameters for fetching the most recent alerts with specific characteristics
query_params_uc1 = {
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

# TODO: update
query_params_uc3 = {
    "size": 1,
    "sort": [{
        "@timestamp": {
            "order": "desc"
        }
    }],
    "query": {
        "bool": {
            "must": [
                {"match": {"agent.ip": "192.168.62.52"}},
                {"match": {"rule.groups": "win_evt_channel"}},
                #{"wildcard": {"rule.description": "*pass-the-hash*"}},
                {"wildcard": {"rule.description": "*Remote Desktop Connection (RDP)*"}},
            ]
        }
    }
}

def fetch_alerts(usecase):
    # Select the appropriate Wazuh server, credentials, and query parameters based on the usecase
    wazuh_server = wazuh_servers.get(usecase)
    auth = credentials.get(usecase)

    # Select the appropriate query parameters
    if usecase == 'uc1':
        query_params = query_params_uc1
    elif usecase == 'uc2':
        query_params = query_params_uc2
    elif usecase == 'uc3':
        query_params = query_params_uc3
    else:
        print(f"Invalid usecase: {usecase}")
        return None

    # Make the request to the Wazuh API with basic authentication
    response = requests.get(
        wazuh_server + endpoint,
        headers=headers,
        json=query_params,
        auth=auth,
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

#fetch_alerts("UC1")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 wazuh.py <usecase (uc1, uc2, uc3)>")
        return
    
    usecase = sys.argv[1]
    alerts = fetch_alerts(usecase)

if __name__ == "__main__":
    main()

