from flask import Flask, jsonify
import requests
from core.constants import PORT, SHUFFLE_API_BASE_URL, SHUFFLE_API_TOKEN

app = Flask(__name__)

def get_workflows():
    headers = {"Authorization": f"Bearer {SHUFFLE_API_TOKEN}"}

    try:
        response = requests.get(SHUFFLE_API_BASE_URL, headers=headers)

        if response.status_code == 200:
            return jsonify(response.json())

        return jsonify({"error": f"Failed to retrieve workflows. Status Code: {response.status_code}"})

    except requests.RequestException as e:
        return jsonify({"error": f"Request to Shuffle API failed: {str(e)}"})

if __name__ == '__main__':
    app.run(port=PORT, debug=True)
