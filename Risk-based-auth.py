import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, roc_auc_score
import concurrent.futures
import joblib

# Load the data
df = pd.read_csv('rba-dataset.csv')

# Function to fill missing values for a single column
def fill_missing_values(column, strategy):
    if strategy == 'median':
        return df[column].fillna(df[column].median())
    elif strategy == 'constant':
        return df[column].fillna('Unknown')

# Function to encode a single column
def encode_column(column):
    le = LabelEncoder()
    df[column] = le.fit_transform(df[column])
    return le

# Fill missing values
with concurrent.futures.ThreadPoolExecutor() as executor:
    futures = []
    futures.append(executor.submit(fill_missing_values, 'Round-Trip Time [ms]', 'median'))
    futures.append(executor.submit(fill_missing_values, 'Region', 'constant'))
    futures.append(executor.submit(fill_missing_values, 'City', 'constant'))
    concurrent.futures.wait(futures)

# Encode categorical variables
label_encoders = {}
categorical_columns = ['IP Address', 'Country', 'Region', 'City', 'ASN', 'User Agent String', 
                       'Browser Name and Version', 'OS Name and Version', 'Device Type']

with concurrent.futures.ThreadPoolExecutor() as executor:
    futures = {executor.submit(encode_column, column): column for column in categorical_columns}
    for future in concurrent.futures.as_completed(futures):
        column = futures[future]
        label_encoders[column] = future.result()

# Define features and target
features = df[['Login Timestamp', 'User ID', 'Round-Trip Time [ms]', 'IP Address', 'Country', 'Region', 
               'City', 'ASN', 'User Agent String', 'Browser Name and Version', 'OS Name and Version', 
               'Device Type', 'Login Successful']]
target = df['Is Attack IP']

# Convert Login Timestamp to datetime and extract features
df['Login Timestamp'] = pd.to_datetime(df['Login Timestamp'])
features['Hour'] = df['Login Timestamp'].dt.hour
features['Day'] = df['Login Timestamp'].dt.day
features['Month'] = df['Login Timestamp'].dt.month
features['Day of Week'] = df['Login Timestamp'].dt.dayofweek

# Drop the original Login Timestamp column
features.drop(columns=['Login Timestamp'], inplace=True)

# Split the data
X_train, X_test, y_train, y_test = train_test_split(features, target, test_size=0.2, random_state=42)

# Train the model using multithreading
def train_model(X_train, y_train):
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)  # Use all available cores
    model.fit(X_train, y_train)
    return model

with concurrent.futures.ThreadPoolExecutor() as executor:
    future = executor.submit(train_model, X_train, y_train)
    model = future.result()

# Make predictions
y_pred = model.predict_proba(X_test)

# Save the model and label encoders for future use (optional)
joblib.dump(model, 'risk_auth_model.pkl')
joblib.dump(label_encoders, 'label_encoders.pkl')

# Evaluate the model
accuracy = accuracy_score(y_test, model.predict(X_test))


print(f'Accuracy: {accuracy}')


