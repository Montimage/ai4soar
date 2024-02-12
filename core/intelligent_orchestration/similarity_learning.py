from sklearn.metrics.pairwise import cosine_similarity, euclidean_distances, manhattan_distances


# Calculate similarity scores using different methods
def calculate_similarity_scores(new_encoded_alert, historical_encoded_alerts, method):
    if method == "cosine":
        similarity_scores = cosine_similarity([new_encoded_alert], historical_encoded_alerts)
        print("Cosine similarity scores:", similarity_scores)
    elif method == "euclidean":
        similarity_scores = euclidean_distances([new_encoded_alert], historical_encoded_alerts)
        print("Euclidean similarity scores:", similarity_scores)
    elif method == "manhattan":
        similarity_scores = manhattan_distances([new_encoded_alert], historical_encoded_alerts)
        print("Manhattan similarity scores:", similarity_scores)
    else:
        raise ValueError("Method should be cosine, euclidean or manhattan!")