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

# Load passwords from an Excel file
passwords_df = pd.read_excel('Unique_Accounts_Password_Research.xlsx')
passwords = passwords_df['password'].tolist()

# Check each password in the Excel file
for password in passwords:
    print(f"Password: {password}, Strength: {check_password_strength(password)}")
print(check_password_strength(password))


"""
# Reading a string character by character
for char in password:
    print(char)

# Categorize integers and letters
letters = ''.join([char for char in password if char.isalpha()])
digits = ''.join([char for char in password if char.isdigit()])

print(f"Letters: {letters}")
print(f"Digits: {digits}")

# Function to check for similarities with account information
def has_similarities(password, first_name, last_name, birthdate, email):
    account_info = [first_name, last_name, birthdate, email]
    for info in account_info:
        if info and info.lower() in password.lower():
            return True
    return False

def common_withaccountinfo(file_path):
    # Load data from CSV file
    df = pd.read_csv(file_path)
    
    # Iterate through each row in the DataFrame
    for index, row in df.iterrows():
        password = row['password']
        first_name = row['first_name']
        last_name = row['last_name']
        birthdate = row['birthdate']
        email = row['email']
        
        # Check for similarities with account information
        if has_similarities(password, first_name, last_name, birthdate, email):
            strength = 0
        else:
            strength = check_password_strength(password)
        
        # Update the DataFrame with the password strength
        df.at[index, 'check_strong'] = 'Strong' if strength == 1 else 'Weak'
    
    # Save the updated DataFrame back to the Excel file
    df.to_excel(file_path, index=False)

common_withaccountinfo('Unique_Accounts_Password_Research.xlsx')
"""
