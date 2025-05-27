import hashlib
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog

def load_common_passwords(filename='common_passwords.txt'):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f]
    except FileNotFoundError:
        messagebox.showwarning("Warning", f"Common passwords file {filename} not found.")
        return []

def determine_hash_algorithm(hash_value):
    hash_length = len(hash_value)
    hash_algorithms = {
        32: 'md5',
        40: 'sha1',
        56: 'sha224',
        64: 'sha256',
        96: 'sha384',
        128: 'sha512'
    }
    return hash_algorithms.get(hash_length, 'sha256')

def evaluate_password_strength(password, common_passwords):
    feedback = []
    score = 0

    if password in common_passwords:
        return {
            'strength': 'Very Weak',
            'feedback': ['Password is found in common password list.']
        }

    length = len(password)
    if length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    diversity_count = sum([has_upper, has_lower, has_digit, has_special])
    score += diversity_count

    if diversity_count < 3:
        feedback.append("Use a mix of uppercase, lowercase, digits, and special characters.")

    charset = 0
    if has_upper:
        charset += 26
    if has_lower:
        charset += 26
    if has_digit:
        charset += 10
    if has_special:
        charset += 32

    entropy = length * (charset ** 0.25)
    if entropy < 30:
        feedback.append("Low entropy; consider increasing length and character variety.")

    if score <= 2:
        strength = 'Weak'
    elif score <= 4:
        strength = 'Medium'
    else:
        strength = 'Strong'

    return {
        'strength': strength,
        'feedback': feedback
    }

def crack_hash(target_hash, common_passwords, hash_algorithm):
    algorithm = getattr(hashlib, hash_algorithm, None)
    if not algorithm:
        return None
    target_hash = target_hash.lower()
    for word in common_passwords:
        hashed_word = algorithm(word.encode('utf-8')).hexdigest()
        if hashed_word == target_hash:
            return word
    return None

def save_results():
    content = output_text.get(1.0, tk.END)
    if not content.strip():
        messagebox.showerror("Error", "No results to save.")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        title="Save Results As"
    )
    if file_path:
        with open(file_path, 'w') as file:
            file.write(content)
        messagebox.showinfo("Success", "Results saved successfully!")

def on_evaluate_click():
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    common_passwords = load_common_passwords()
    result = evaluate_password_strength(password, common_passwords)
    
    output_text.config(state=tk.NORMAL)
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Password Strength: {result['strength']}\n")
    if result['feedback']:
        output_text.insert(tk.END, "\nFeedback:\n")
        for msg in result['feedback']:
            output_text.insert(tk.END, f"- {msg}\n")
    output_text.config(state=tk.DISABLED)

def on_crack_click():
    target_hash = hash_entry.get()
    if not target_hash:
        messagebox.showerror("Error", "Please enter a hash.")
        return

    common_passwords = load_common_passwords()
    algo = determine_hash_algorithm(target_hash)
    cracked = crack_hash(target_hash, common_passwords, algo)
    
    output_text.config(state=tk.NORMAL)
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Hash Algorithm: {algo.upper()}\n")
    if cracked:
        output_text.insert(tk.END, f"Cracked Password: {cracked}\n")
    else:
        output_text.insert(tk.END, "Failed to crack the hash.\n")
    output_text.config(state=tk.DISABLED)

# Create the main window
root = tk.Tk()
root.title("Password Strength & Hash Cracker")
root.geometry("600x450")

# Password Evaluation Section
password_frame = tk.LabelFrame(root, text="Password Strength Evaluation", padx=10, pady=10)
password_frame.pack(padx=10, pady=5, fill="x")

tk.Label(password_frame, text="Enter Password:").pack()
password_entry = tk.Entry(password_frame, width=50)
password_entry.pack()

evaluate_button = tk.Button(password_frame, text="Evaluate Password", command=on_evaluate_click)
evaluate_button.pack(pady=5)

# Hash Cracking Section
hash_frame = tk.LabelFrame(root, text="Hash Cracking", padx=10, pady=10)
hash_frame.pack(padx=10, pady=5, fill="x")

tk.Label(hash_frame, text="Enter Hash:").pack()
hash_entry = tk.Entry(hash_frame, width=50)
hash_entry.pack()

crack_button = tk.Button(hash_frame, text="Crack Hash", command=on_crack_click)
crack_button.pack(pady=5)

# Output Section
output_frame = tk.LabelFrame(root, text="Results", padx=10, pady=10)
output_frame.pack(padx=10, pady=5, fill="both", expand=True)

output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=70, height=10)
output_text.pack(fill="both", expand=True)
output_text.config(state=tk.DISABLED)

# Save Results Button
save_button = tk.Button(root, text="Save Results", command=save_results)
save_button.pack(pady=10)

root.mainloop()