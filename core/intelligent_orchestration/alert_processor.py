import numpy as np
import tensorflow as tf
import os
import json
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.models import Model
from similarity_learning import calculate_similarity_scores
#from constants import SELECTED_FEATURES

# Relevant keys for one-hot encoding
SELECTED_FEATURES = ["srcip", "srcport", "dstip", "hostname", "technique"]

MITRE_TECHNIQUES = ['Password Guessing', 'SSH', 'Password Cracking']

def convert_one_hot_alert(alert):
    one_hot_vector = {}

    # Extract the "technique" field from the alert's data
    if "mitre" in alert["_source"]["rule"] and "technique" in alert["_source"]["rule"]["mitre"]:
        techniques = alert["_source"]["rule"]["mitre"]["technique"]
    else:
        techniques = []

    # Extract other fields like "srcip", "srcport", "dstip", "hostname", etc.
    data = alert["_source"]["data"]
    srcip = data.get("srcip", None)
    srcport = data.get("srcport", None)
    dstuser = data.get("dstuser", None)
    hostname = alert["_source"]["predecoder"]["hostname"]

    # Create one-hot encoding for each selected feature
    for feature in SELECTED_FEATURES:
        if feature == "technique":
            for technique in MITRE_TECHNIQUES:
                if technique in techniques:
                    one_hot_vector[technique] = 1
                else:
                    one_hot_vector[technique] = 0
        elif feature == "srcip":
            if srcip:
                srcip_feature = "srcip-" + srcip
                one_hot_vector[srcip_feature] = 1
            else:
                one_hot_vector["srcip"] = 0
        elif feature == "srcport":
            if srcport:
                srcport_feature = "srcport-" + srcport
                one_hot_vector[srcport_feature] = 1
            else:
                one_hot_vector["srcport"] = 0
        elif feature == "dstuser":
            if dstuser:
                dstuser_feature = "dstuser-" + dstuser
                one_hot_vector[dstuser_feature] = 1
            else:
                one_hot_vector["dstuser"] = 0
        elif feature == "hostname":
            one_hot_vector["hostname"] = 1 if hostname else 0

    print("Original alert:")
    print(alert)
    print("\nOne-hot vector:")
    print(one_hot_vector)

    return one_hot_vector

def convert_one_hot_alerts(all_alerts):
    num_features = len(all_alerts[0].keys())
    one_hot_vectors_alerts = []

    for alert in all_alerts:
        one_hot_vector = convert_one_hot_alert(alert)
        one_hot_vectors_alerts.append(one_hot_vector)

    one_hot_vectors_alerts = np.array(one_hot_vectors_alerts)
    print("\nOne-hot vectors:")
    print(one_hot_vectors_alerts)

    return one_hot_vectors_alerts

def encode_alerts(one_hot_vectors_alerts):
    # Extract keys from the first alert to ensure consistent order
    keys = list(one_hot_vectors_alerts[0].keys())

    # Convert dictionaries to numpy arrays
    one_hot_vectors_array = np.array([[alert.get(key, 0) for key in keys] for alert in one_hot_vectors_alerts])

    # Set random seed for reproducibility ?
    tf.random.set_seed(42)

    # Define an autoencoder model
    input_dim = len(keys)
    encoding_dim = 3

    input_layer = Input(shape=(input_dim,))
    encoded = Dense(encoding_dim, activation='relu')(input_layer)
    decoded = Dense(input_dim, activation='sigmoid')(encoded)

    autoencoder = Model(input_layer, decoded)
    autoencoder.compile(optimizer='adam', loss='binary_crossentropy')

    # Train the autoencoder
    autoencoder.fit(one_hot_vectors_array, one_hot_vectors_array, epochs=1000, verbose=0)

    # Encode the alerts using the trained autoencoder
    encoded_alerts = autoencoder.predict(one_hot_vectors_array)

    print("\nEncoded alerts:")
    print(encoded_alerts)

    return encoded_alerts

if __name__ == '__main__':
    ALERTS_DIR = "../../tests/alerts"
    all_alerts = []

    # Iterate over each file in the alerts folder
    for filename in os.listdir(ALERTS_DIR):
        if filename.endswith('.json'):
            file_path = os.path.join(ALERTS_DIR, filename)
            with open(file_path, 'r') as file:
                alert = json.load(file)
                all_alerts.append(alert)

    one_hot_alerts = convert_one_hot_alerts(all_alerts)
    historical_encoded_alerts = encode_alerts(one_hot_alerts)

    # Testing similarity scores
    new_encoded_alert = np.array([0.99059486,0.94087994,0.98448485,0.9757894,0.9952647,0.03528981])
    similarity_scores = calculate_similarity_scores(new_encoded_alert, historical_encoded_alerts, "cosine")