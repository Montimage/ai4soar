"""
Legacy Shuffle module for backward compatibility.
New code should use core.services.PlaybookService instead.
"""

from flask import Flask, request, jsonify
import requests
from core.config import config

app = Flask(__name__)
shuffle_config = config.shuffle
headers = shuffle_config.get_headers()

def get_playbooks():
    execute_url = f"{shuffle_config.api_base_url}/workflows"

    try:
        response = requests.get(execute_url, headers=headers)
        playbooks = response.json()
        #print(playbooks)
        playbook_names = [playbook["name"] for playbook in playbooks]
        playbook_ids = [playbook["id"] for playbook in playbooks]
        playbook_descriptions = [playbook["description"] for playbook in playbooks]
        for name, _id, description in zip(playbook_names, playbook_ids, playbook_descriptions):
            print(f"Workflow name: {name}, id: {_id}, description: {description}")

        if response.status_code == 200:
            # Create a list of dictionaries containing id, name, and description for each playbook
            playbook_data = [{
                                "id": playbook["id"],
                                "name": playbook["name"],
                                "description": playbook["description"]
                            } for playbook in playbooks]
            return playbook_data

        return jsonify({"error": f"Failed to retrieve playbooks. Status Code: {response.status_code}"})

    except requests.RequestException as e:
        return jsonify({"error": f"Request to Shuffle API failed: {str(e)}"})

def execute_playbook(playbook_id):
    execute_url = f"{shuffle_config.api_base_url}/workflows/{playbook_id}/execute"
    data = request.get_json()

    try:
        response = requests.post(execute_url, headers=headers, json=data)

        if response.status_code == 200:
            return jsonify(response.json())

        return jsonify({"error": f"Failed to execute playbook. Status Code: {response.status_code}"})

    except requests.RequestException as e:
        return jsonify({"error": f"Request to Shuffle API failed: {str(e)}"})

def get_playbook_results():
    """Get playbook execution results."""
    execute_url = f"{shuffle_config.api_base_url}/streams/results"
    data = request.get_json()

    try:
        response = requests.post(execute_url, headers=headers, json=data)

        if response.status_code == 200:
            return jsonify(response.json()["result"])

        return jsonify({"error": f"Failed to execute playbook. Status Code: {response.status_code}"})

    except requests.RequestException as e:
        return jsonify({"error": f"Request to Shuffle API failed: {str(e)}"})


if __name__ == '__main__':
    app.run(port=config.server.port, debug=True)
