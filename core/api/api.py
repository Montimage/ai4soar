import numpy as np
import requests
from flask import Flask, request, jsonify
from core.playbook_consumer.playbook_processor import connect_to_mongodb, list_all_historical_alerts, get_playbook_id_for_alert
from core.intelligent_orchestration.alert_processor import convert_one_hot_alert, convert_one_hot_alerts, encode_alerts
from core.intelligent_orchestration.similarity_learning import calculate_similarity_scores
from core.orchestration_engine.shuffle import get_playbooks, execute_playbook, get_playbook_results
from core.constants import SERVER_IP, PORT, SHUFFLE_API_BASE_URL
from core.orchestration_engine.caldera_soar import execute_ability

app = Flask(__name__)

# Execute Caldera blue agent
@app.route('/execute_ability', methods=['POST'])
def execute_ability_api():
    try:
        ability_id = request.form.get('ability_id')
        target = request.form.get('target')
        #data = request.get_json()
        #ability_id = data['ability_id']
        #target = data['target']

        if not ability_id or not target:
            return jsonify({'error': 'Invalid input'}), 400

        # Call execute_ability function
        response = execute_ability(ability_id, target)

        return jsonify({'message': 'Ability execution initiated successfully', 'response': response.text}), 200

    except KeyError as e:
        return jsonify({'error': f'Missing required parameter: {str(e)}'}), 400

    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# List all playbook's information, including id, name and description
# or a specific playbook's information
@app.route('/playbooks', methods=['GET'])
def get_playbooks_route():
    playbook_id = request.args.get('playbook_id')
    playbooks = get_playbooks()

    if playbook_id:
        # If playbook_id is provided, fetch information about the specific playbook
        for playbook in playbooks:
            if playbook["id"] == playbook_id:
                return jsonify(playbook)
        return jsonify({"error": f"Playbook with ID {playbook_id} not found."}), 404
    else:
        # If playbook_id is not provided, fetch information about all playbooks
        playbook_data = []
        for playbook in playbooks:
            playbook_info = {
                "id": playbook["id"],
                "name": playbook["name"],
                "description": playbook["description"]
            }
            playbook_data.append(playbook_info)
        return jsonify(playbook_data)

# Execute a playbook given its id
@app.route('/playbooks/<playbook_id>/execute', methods=['POST'])
def execute_playbook_route(playbook_id):
    return execute_playbook(playbook_id)

# Get playbook execution results
@app.route('/playbooks/results', methods=['POST'])
def get_playbook_results_route():
    return get_playbook_results()

# Get all historical alerts
@app.route('/historical_alerts', methods=['GET'])
def get_historical_alerts_route():
    alerts_collection, _ = connect_to_mongodb()
    historical_alerts = list_all_historical_alerts(alerts_collection)
    return jsonify(historical_alerts)

# Get a playbook associated with the alert
@app.route('/playbook/<alert_id>', methods=['GET'])
def get_playbook_for_alert_route(alert_id):
    alerts_collection, _ = connect_to_mongodb()
    historical_alerts = list_all_historical_alerts(alerts_collection)

    playbook_id = None
    for alert in historical_alerts:
        if alert.get('_id') == alert_id:
            playbook_id = alert.get('playbook_id')
            break
    if playbook_id:
        return jsonify({"playbook_id": playbook_id})
    return jsonify({"error": f"No playbook found for alert ID {alert_id}"}), 404

# Encode all historical alerts
@app.route('/encode/historical_alerts', methods=['GET'])
def encode_historical_alerts_route():
    alerts_collection, _ = connect_to_mongodb()
    historical_alerts = list_all_historical_alerts(alerts_collection)
    one_hot_alerts = convert_one_hot_alerts(historical_alerts)
    historical_encoded_alerts = encode_alerts(one_hot_alerts)
    return jsonify({"encoded_alerts": historical_encoded_alerts.tolist()})

# Encode a new alert, which is sent as json in the request body
@app.route('/encode/new_alert_json', methods=['POST'])
def encode_new_alert_json_route():
    new_alert = request.json
    one_hot_alert = convert_one_hot_alert(new_alert)
    new_encoded_alert = encode_alerts(np.array([one_hot_alert]))
    return jsonify({"encoded_alert": new_encoded_alert.tolist()})

# Encode a new alert based on its "_id" in the request body
@app.route('/encode/new_alert_id', methods=['POST'])
def encode_new_alert_id_route():
    alert_id = request.json.get("_id")
    if not alert_id:
        return jsonify({"error": "Alert _id not provided in the request."}), 400

    alerts_collection, _ = connect_to_mongodb()
    new_alert = alerts_collection.find_one({"_id": alert_id})
    if not new_alert:
        return jsonify({"error": "Alert not found."}), 404

    one_hot_alert = convert_one_hot_alert(new_alert)
    new_encoded_alert = encode_alerts(np.array([one_hot_alert]))
    return jsonify({"encoded_alert": new_encoded_alert.tolist()})

# Calculate similarity scores of an alert based on its "_id" in the request body
@app.route('/similarity_scores', methods=['POST'])
def calculate_similarity_route():
    try:
        data = request.json
        alert_id = data.get('_id')
        method = data.get('method')

        if alert_id is None or method is None:
            raise ValueError("Please provide '_id' and 'method' in the request body.")

        # Retrieve the new alert from the database based on its _id
        alerts_collection, _ = connect_to_mongodb()
        new_alert = alerts_collection.find_one({"_id": alert_id})

        if new_alert is None:
            raise ValueError(f"No alert found with _id '{alert_id}'.")

        # Convert and encode the new alert
        one_hot_alert = convert_one_hot_alert(new_alert)
        new_encoded_alert = encode_alerts(np.array([one_hot_alert]))

        # Calculate similarity scores
        historical_alerts = list_all_historical_alerts(alerts_collection)
        one_hot_alerts = convert_one_hot_alerts(historical_alerts)
        historical_encoded_alerts = encode_alerts(one_hot_alerts)
        similarity_scores = calculate_similarity_scores(new_encoded_alert, historical_encoded_alerts, method)

        return jsonify({"similarity_scores": similarity_scores.tolist()})

    except Exception as e:
        return jsonify({"error": str(e)})

# Fetch playbook information using playbook id
def fetch_playbook_info(playbook_id):
    execute_url = f"http://localhost:{PORT}/playbooks?playbook_id={playbook_id}"

    try:
        response = requests.get(execute_url)
        playbook_data = response.json()

        if response.status_code == 200:
            return playbook_data
        else:
            return {"error": f"Failed to retrieve playbook with id {playbook_id}. Status Code: {response.status_code}"}

    except requests.RequestException as e:
        return {"error": f"Request to Shuffle API failed: {str(e)}"}

# Identify top-k most similar alerts and extract corresponding playbooks
@app.route('/top_k_similar_alerts', methods=['POST'])
def identify_top_k_similar_alerts_route():
    try:
        data = request.json
        similarity_scores = data.get('similarity_scores')
        k = data.get('k')

        if similarity_scores is None or k is None:
            raise ValueError("Please provide 'similarity_scores' and 'k' in the request body.")

        # Extract similarity scores from the nested list
        similarity_scores = similarity_scores[0]
        print(similarity_scores)

        # Sort similarity scores in descending order and select top-k indices
        top_k_indices = sorted(range(len(similarity_scores)), key=lambda i: similarity_scores[i], reverse=True)[:k]
        print(top_k_indices)

        # Fetch playbook information for each similar alert
        similar_alerts = []
        alerts_collection, _ = connect_to_mongodb()
        historical_alerts = list_all_historical_alerts(alerts_collection)
        playbook_data_list = []
        for id in top_k_indices:
            alert_id = historical_alerts[id]["_id"]
            playbook_id = get_playbook_id_for_alert(alert_id)
            playbook_data = fetch_playbook_info(playbook_id)
            #print(playbook_data)
            playbook_data_list.append(playbook_data)

        return jsonify({"playbooks": playbook_data_list})

    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == '__main__':
    app.run(host=SERVER_IP, port=PORT, debug=True)
