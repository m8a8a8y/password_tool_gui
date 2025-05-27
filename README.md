📘 Project Documentation: Password Strength & Hash Cracker

🔧 Project Overview:

The Password Strength & Hash Cracker is a Python GUI application built using tkinter. It provides two main functionalities:

Password Strength Evaluation – Analyzes a user-entered password and provides strength feedback.

Hash Cracking – Attempts to reverse a given hash using a dictionary attack with a common password list.


🗂️ Project Structure
bash
Copy
Edit
PasswordStrengthAndHashCracker/

├── main.py                  # Main application script

├── common_passwords.txt     # List of commonly used passwords (dictionary file)






🧰 Dependencies
Python 3.x
tkinter (comes built-in with standard Python distributions)



🚀 How to Run the Project
Make sure Python 3 is installed.

Ensure the common_passwords.txt file is present in the same directory.

Run the script:

bash
Copy
Edit
python main.py


💡 Features:

1. Password Strength Evaluation
Checks if the password exists in a dictionary of common passwords.

Evaluates strength based on:

Length
Character diversity (uppercase, lowercase, digits, special characters)
Entropy estimation

Categorizes strength as:
Very Weak
Weak
Medium
Strong

Displays actionable feedback.


2. Hash Cracking
Accepts a hash value from the user.

Automatically detects the hash algorithm based on hash length:

MD5 (32)
SHA-1 (40)
SHA-224 (56)
SHA-256 (64)
SHA-384 (96)
SHA-512 (128)

Performs a dictionary attack using common passwords.

Displays cracked password if found, or failure message otherwise.


3. Save Results
Allows saving the output (evaluation or cracking result) to a .txt file via file dialog.

🧠 Core Functions Explained
load_common_passwords(filename)
Loads the list of common passwords for use in both evaluation and hash cracking.

evaluate_password_strength(password, common_passwords)
Returns a dictionary with strength level and feedback list based on heuristics and entropy calculation.

determine_hash_algorithm(hash_value)
Maps the length of the hash to a known algorithm.

crack_hash(target_hash, common_passwords, hash_algorithm)
Attempts to reverse the hash using hashlib and compare hashes from the common passwords list.

🖼️ GUI Layout
Section	Description
Password Strength Evaluation	Input field + button to evaluate password strength
Hash Cracking	Input field + button to attempt to crack a hash
Results	A ScrolledText widget that displays the output
Save Results	Saves displayed results to a text file

📄 common_passwords.txt
This file should contain one password per line. It is used both for detecting weak passwords and for hash cracking attempts.

Example:

pgsql
Copy
Edit
123456
password
qwerty
letmein
admin

🔒 Security Considerations
The application uses only local dictionary attacks and does not perform online brute-force or rainbow table attacks.

Ensure your common_passwords.txt is regularly updated to include the most frequently leaked passwords for better accuracy.

📚 References
Python hashlib documentation

NIST Password Guidelines

OWASP Password Storage Cheat Sheet

