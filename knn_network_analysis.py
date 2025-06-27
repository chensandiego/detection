import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import numpy as np

# This is a simplified example. In a real-world scenario, you would download the dataset.
# For this script, we will simulate a small portion of the NSL-KDD dataset.
# The dataset has 41 features and a final column for the label ('normal' or an attack type).

# Step 1: Create a simulated dataset for demonstration purposes
# In a real scenario, you would load this from a file e.g., pd.read_csv('KDDTrain+.txt')
data = {
    'duration': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    'protocol_type': ['tcp', 'udp', 'tcp', 'tcp', 'udp', 'tcp', 'tcp', 'udp', 'tcp', 'tcp'],
    'service': ['ftp_data', 'other', 'private', 'http', 'other', 'http', 'private', 'other', 'http', 'ftp_data'],
    'flag': ['SF', 'SF', 'S0', 'SF', 'SF', 'SF', 'REJ', 'SF', 'S0', 'SF'],
    'src_bytes': [491, 146, 0, 232, 199, 300, 0, 150, 0, 520],
    'dst_bytes': [0, 0, 0, 8153, 200, 4000, 0, 150, 0, 0],
    # ... (imagine 35 more feature columns here)
    'label': ['normal', 'normal', 'neptune', 'normal', 'normal', 'normal', 'smurf', 'normal', 'neptune', 'normal']
}
# To make the example runnable, we'll add some dummy columns for the other features
for i in range(35):
    data[f'feature_{i}'] = np.random.randint(0, 1000, 10)

df = pd.DataFrame(data)

# Convert the 'label' column to binary: 1 for 'attack' (anything not 'normal'), 0 for 'normal'
df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

# Step 2: Preprocess the Data
# Separate features (X) and target label (y)
X = df.drop('label', axis=1)
y = df['label']

# Encode categorical features
categorical_cols = ['protocol_type', 'service', 'flag']
for col in categorical_cols:
    le = LabelEncoder()
    X[col] = le.fit_transform(X[col])

# Step 3: Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Step 4: Scale numerical features
# This is crucial for distance-based algorithms like KNN
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Step 5: Train the KNN Classifier
k = 5  # The number of neighbors to consider
knn = KNeighborsClassifier(n_neighbors=k)
knn.fit(X_train, y_train)

# Step 6: Make Predictions
y_pred = knn.predict(X_test)

# Step 7: Evaluate the Model
accuracy = accuracy_score(y_test, y_pred)
conf_matrix = confusion_matrix(y_test, y_pred)
class_report = classification_report(y_test, y_pred)

print(f"--- KNN Model Evaluation ---")
print(f"Accuracy: {accuracy:.4f}")
print("\nConfusion Matrix:")
print(conf_matrix)
print("\nClassification Report:")
print(class_report)

# Example of classifying a new, single data point
# This would represent a new network connection you want to classify in real-time.
# Note: It must be preprocessed in the exact same way as the training data.
new_connection = X.iloc[0].values.reshape(1, -1) # taking the first row as an example
scaled_new_connection = scaler.transform(new_connection)
prediction = knn.predict(scaled_new_connection)

print("\n--- New Connection Prediction ---")
print(f"Prediction for the new data point: {'Malicious' if prediction[0] == 1 else 'Normal'}")
