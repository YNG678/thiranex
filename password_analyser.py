import re
import secrets
import string
import hashlib

class PasswordAnalyzer:
    def __init__(self):
        self.alphabet = string.ascii_letters + string.digits + string.punctuation

    def evaluate(self, password):
        score = 0
        feedback = []
        
        if len(password) < 8:
            feedback.append("Password is too short. Minimum 8 characters needed.")
        elif len(password) >= 12:
            score += 2
        else:
            score += 1

        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters.")
            
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters.")
            
        if re.search(r'[0-9]', password):
            score += 1
        else:
            feedback.append("Add numbers.")
            
        if re.search(r'[^A-Za-z0-9]', password):
            score += 1
        else:
            feedback.append("Add special characters (e.g., @, #, $, !).")

        final_score = min(score, 5)
        
        return {
            "score": final_score,
            "feedback": feedback if feedback else ["Password looks strong!"],
            "is_strong": final_score >= 4
        }

    def generate_alternative(self, length=16):
        while True:
            pwd = ''.join(secrets.choice(self.alphabet) for i in range(length))
            if (any(c.islower() for c in pwd)
                    and any(c.isupper() for c in pwd)
                    and sum(c.isdigit() for c in pwd) >= 2
                    and any(c in string.punctuation for c in pwd)):
                return pwd

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    
    hash_key = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt.encode('utf-8'), 
        100000
    )
    return salt, hash_key.hex()

def is_password_reused(new_password, stored_salt, stored_hash):
    _, new_hash = hash_password(new_password, stored_salt)
    return new_hash == stored_hash            

if __name__ == "__main__":
    analyzer = PasswordAnalyzer()
    
    print("=======================================")
    print("🔒 Welcome to the Password Security Tool")
    print("=======================================\n")
    
    while True:
        print("Choose an option:")
        print("1. Analyze a password")
        print("2. Generate a secure password alternative")
        print("3. Exit")
        
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == '1':
            user_pwd = input("Enter password to analyze: ")
            result = analyzer.evaluate(user_pwd)
            
            print("\n--- Analysis Results ---")
            print(f"Score: {result['score']}/5")
            print(f"Status: {'🟢 Strong' if result['is_strong'] else '🔴 Weak'}")
            print("Feedback:")
            for item in result['feedback']:
                print(f" - {item}")
            print("------------------------\n")
            
        elif choice == '2':
            suggested = analyzer.generate_alternative()
            print("\n------------------------------------")
            print(f"💡 Suggested Secure Password:\n👉 {suggested}")
            print("------------------------------------\n")
            
        elif choice == '3':
            print("Goodbye! Stay secure.")
            break
        else:
            print("❌ Invalid option. Please choose 1, 2, or 3.\n")