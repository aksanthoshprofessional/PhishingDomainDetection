import pandas as pd
import numpy as np
import os
import joblib
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Load dataset
data = "data\dataset_small.csv"
df = pd.read_csv(data)

# Drop missing values
df = df.dropna()

# Separate features and target
y = df["phishing"]
x = df.drop("phishing", axis=1)

# Save feature names for later use
feature_names = x.columns

# Define the directory where you want to save
save_dir = "model\\"

# Ensure the directory exists
os.makedirs(save_dir, exist_ok=True)

# Save feature names
feature_names_path = os.path.join(save_dir, "Feature_Names.pkl")
joblib.dump(x.columns, feature_names_path)

print(f"Feature names saved to: {feature_names_path}")


# Split the dataset
X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)

# Train the model
model = HistGradientBoostingClassifier()
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy:.4f}")
print(classification_report(y_test, y_pred))
# Define the directory where you want to save
save_dir_1 = "model\\"

# Ensure the directory exists
os.makedirs(save_dir_1, exist_ok=True)

# Save feature names
phishing_model_path = os.path.join(save_dir, "Phishing_Model.pkl")
joblib.dump(model,phishing_model_path)

print(f"Feature names saved to: {phishing_model_path}")

print("Model saved as Phishing_Model.pkl")
