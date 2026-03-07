import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Load dataset
dataset_path = "../scripts/network_dataset.csv"
data = pd.read_csv(dataset_path)

# Separate features and labels
X = data.drop("label", axis=1)
y = data["label"]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Create Random Forest model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

# Train model
model.fit(X_train, y_train)

# Test model
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print("Model Accuracy:", accuracy)

# Save trained model
model_path = "mitm_rf_model.pkl"
joblib.dump(model, model_path)

print("Model saved successfully as mitm_rf_model.pkl")