import joblib

# Load trained model
model = joblib.load("threat_model.pkl")

# Print the expected feature names
print(model.feature_names_in_)
