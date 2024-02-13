from flask import Flask, request, jsonify
import requests
from core.constants import PORT, SHUFFLE_API_BASE_URL, SHUFFLE_API_TOKEN

app = Flask(__name__)
headers = {"Authorization": f"Bearer {SHUFFLE_API_TOKEN}"}

def get_workflows():
    execute_url = f"{SHUFFLE_API_BASE_URL}/workflows"

    try:
        response = requests.get(execute_url, headers=headers)
        workflows = response.json()
        #print(workflows)
        workflow_names = [workflow["name"] for workflow in workflows]
        workflow_ids = [workflow["id"] for workflow in workflows]
        workflow_descriptions = [workflow["description"] for workflow in workflows]
        for name, _id, description in zip(workflow_names, workflow_ids, workflow_descriptions):
            print(f"Workflow name: {name}, id: {_id}, description: {description}")

        if response.status_code == 200:
            # Create a list of dictionaries containing id, name, and description for each workflow
            workflow_data = [{
                                "id": workflow["id"],
                                "name": workflow["name"],
                                "description": workflow["description"]
                            } for workflow in workflows]
            return jsonify(workflow_data)

        return jsonify({"error": f"Failed to retrieve workflows. Status Code: {response.status_code}"})

    except requests.RequestException as e:
        return jsonify({"error": f"Request to Shuffle API failed: {str(e)}"})

def execute_workflow(workflow_id):
    execute_url = f"{SHUFFLE_API_BASE_URL}/workflows/{workflow_id}/execute"
    data = request.get_json()

    try:
        response = requests.post(execute_url, headers=headers, json=data)

        if response.status_code == 200:
            return jsonify(response.json())

        return jsonify({"error": f"Failed to execute workflow. Status Code: {response.status_code}"})

    except requests.RequestException as e:
        return jsonify({"error": f"Request to Shuffle API failed: {str(e)}"})

# TODO: parameters "execution_id" and "authorization" extracted from execute_workflow()
def get_workflow_results():
    execute_url = f"{SHUFFLE_API_BASE_URL}/streams/results"
    data = request.get_json()

    try:
        response = requests.post(execute_url, headers=headers, json=data)

        if response.status_code == 200:
            return jsonify(response.json()["result"])

        return jsonify({"error": f"Failed to execute workflow. Status Code: {response.status_code}"})

    except requests.RequestException as e:
        return jsonify({"error": f"Request to Shuffle API failed: {str(e)}"})


if __name__ == '__main__':
    app.run(port=PORT, debug=True)
