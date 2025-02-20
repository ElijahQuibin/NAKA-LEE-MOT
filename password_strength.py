"""
MODEL SIMULATION FINALS PROJECT BY NAKA-LEE-MOT

This is a password strength checker that checks the strength of a password based on the following criteria:
- The password must be at least 12 characters long.
- The password must contain at least one uppercase letter.
- The password must contain at least one lowercase letter.
- The password must contain at least one digit.
- The password must contain at least one special character.
- The password must not be a common password.
"""

import re
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

# Defining variables
min_length = 12
uppercase_pattern = r'[A-Z]'
lowercase_pattern = r'[a-z]'
digit_pattern = r'\d'
special_char_pattern = r'[!@#$%^&*(),.?":{}|<>_]'
common_passwords = pd.read_csv('common_passwords.csv')['password'].tolist() # Load common passwords from a CSV file

def check_password_strength(password):
    # Check length
    if len(password) < min_length:
        return 0

    # Check for uppercase letters
    if not re.search(uppercase_pattern, password):
        return 0

    # Check for lowercase letters
    if not re.search(lowercase_pattern, password):
        return 0

    # Check for digits
    if not re.search(digit_pattern, password):
        return 0

    # Check for special characters
    if not re.search(special_char_pattern, password):
        return 0

    # Check if the password is common
    if password in common_passwords:
        return 0

    # If all criteria are met, the password is strong
    return 1

# Function to check for similarities with account information
def has_similarities(password, first_name, last_name, birthdate, email):
    account_info = [first_name, last_name, birthdate, email]
    for info in account_info:
        if info and info.lower() in password.lower():
            return True
    return False

# Function to extract features from a password
def extract_features(row):
    password = row['password']
    first_name = row['first_name']
    last_name = row['last_name']
    birthdate = row['birthdate']
    email = row['email']
    
    return [
        len(password) >= min_length,
        bool(re.search(uppercase_pattern, password)),
        bool(re.search(lowercase_pattern, password)),
        bool(re.search(digit_pattern, password)),
        bool(re.search(special_char_pattern, password)),
        password not in common_passwords,
        not has_similarities(password, first_name, last_name, birthdate, email)
    ]

# Load dataset from Excel file
data = pd.read_excel('Unique_Accounts_Password_Research.xlsx')  # Excel file with 'password', 'strength', 'first_name', 'last_name', 'birthdate', 'email' columns
data['features'] = data.apply(extract_features, axis=1)
X = list(data['features'])
y = data['strength']

# Split the dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the logistic regression model
model = LogisticRegression()
model.fit(X_train, y_train)

# Predict and evaluate the model
y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred)}")

# Example usage with logistic regression model
password = "y65ourpassword123!"
account_info = {
    'first_name': 'John',
    'last_name': 'Doe',
    'birthdate': '1990-01-01',
    'email': 'john.doe@example.com'
}
features = [extract_features({**account_info, 'password': password})]
print(f"Password strength prediction: {model.predict(features)[0]}")
