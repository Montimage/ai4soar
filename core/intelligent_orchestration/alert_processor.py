import numpy as np
import tensorflow as tf
import json
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.models import Model
#from constants import SELECTED_FEATURES

# Relevant keys for one-hot encoding
SELECTED_FEATURES = ["srcip", "dstip", "hostname"]

# Parse the given alerts, if needed
def parse_alert(alert):
    parsed_alert = {}

    for key, value in alert.items():
        if isinstance(value, dict):
            parsed_alert[key] = parse_alert(value)
        elif isinstance(value, str) and value.lower() == "null":
            parsed_alert[key] = None
        else:
            parsed_alert[key] = value
    return parsed_alert

def alerts_to_one_hot_vectors(alert):
    alert_keys = alert.keys()
    one_hot_vector = {key: 1 if key in alert_keys else 0 for key in SELECTED_FEATURES}

    print("Original Alert:")
    print(alert)
    print("\nOne-Hot Vector:")
    print(one_hot_vector)

    # Dummy alert dictionaries
    alerts_dict = [
        {"srcip": 1, "dstip": 0, "hostname": 1, "timestamp": 0, "severity": 0},
        {"srcip": 0, "dstip": 1, "hostname": 0, "timestamp": 1, "severity": 0},
        {"srcip": 1, "dstip": 1, "hostname": 1, "timestamp": 0, "severity": 0},
    ]

    num_features = len(SELECTED_FEATURES)
    one_hot_vectors_alerts = []

    for alert_dict in alerts_dict:
        one_hot_vector = [alert_dict.get(feature, 0) for feature in SELECTED_FEATURES]
        one_hot_vectors_alerts.append(one_hot_vector)

    one_hot_vectors_alerts = np.array(one_hot_vectors_alerts)
    print("\nOne-Hot Vectors:")
    print(one_hot_vectors_alerts)

    return one_hot_vectors_alerts

def autoencoder_alerts(one_hot_vectors_alerts):
    # Define an autoencoder model
    input_dim = one_hot_vectors_alerts.shape[1]
    encoding_dim = 3

    input_layer = Input(shape=(input_dim,))
    encoded = Dense(encoding_dim, activation='relu')(input_layer)
    decoded = Dense(input_dim, activation='sigmoid')(encoded)

    autoencoder = Model(input_layer, decoded)
    autoencoder.compile(optimizer='adam', loss='binary_crossentropy')

    # Train the autoencoder
    autoencoder.fit(one_hot_vectors_alerts, one_hot_vectors_alerts, epochs=1000, verbose=0)

    # Encode the alerts using the trained autoencoder
    encoded_alerts = autoencoder.predict(one_hot_vectors_alerts)

    print("\nEncoded Alerts:")
    print(encoded_alerts)

    return encoded_alerts

if __name__ == '__main__':
    # Read the alert from a JSON file
    with open('wazuh_alert.json', 'r') as file:
        wazuh_alert = json.load(file)
        one_hot_vectors_alerts = alerts_to_one_hot_vectors(wazuh_alert)
        encoded_alerts = autoencoder_alerts(one_hot_vectors_alerts)