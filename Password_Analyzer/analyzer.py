#!/usr/bin/env python3
"""
A GUI and CLI password strength checker with suggestions and generator.
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import re
import random
import string
import logging
import json
import argparse
import sys
from functools import lru_cache

try:
    from zxcvbn import zxcvbn
except ImportError:
    print("Error: 'zxcvbn' not installed. Run: pip install zxcvbn")
    sys.exit(1)

logging.basicConfig(filename='password_checker.log', level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')


class Wordlist:
    _cache = {}

    def __init__(self, file_path):
        self.file_path = file_path
        self.words = self.load_wordlist()

    def load_wordlist(self):
        if self.file_path in self._cache:
            return self._cache[self.file_path]
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                words = [line.strip() for line in f]
                self._cache[self.file_path] = words
                return words
        except Exception:
            return []

    def is_word_in_list(self, word):
        return word in self.words


class StrengthResult:
    def __init__(self, strength, score, message):
        self.strength = strength
        self.score = score
        self.message = message


class PasswordStrength:
    def __init__(self, weak_path="weak_passwords.txt", banned_path="banned_passwords.txt"):
        self.weak_words = Wordlist(weak_path)
        self.banned_words = Wordlist(banned_path)
        self.min_len = 12
        self.score_map = {
            0: "Very Weak", 1: "Weak", 2: "Moderate", 3: "Strong", 4: "Very Strong"
        }

    @lru_cache(maxsize=1000)
    def check_password_strength(self, password):
        if len(password) < self.min_len:
            return StrengthResult("Too Short", 0, "Minimum 12 characters required.")

        if self.weak_words.is_word_in_list(password):
            return StrengthResult("Weak", 0, "Password is too common.")

        if self.banned_words.is_word_in_list(password):
            return StrengthResult("Banned", 0, "Password is banned due to leaks.")

        result = zxcvbn(password)
        score = result["score"]
        strength = self.score_map[score]
        issues = []

        if not re.search(r'[A-Z]', password):
            issues.append("uppercase")
        if not re.search(r'[a-z]', password):
            issues.append("lowercase")
        if not re.search(r'\d', password):
            issues.append("digit")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            issues.append("special char")

        if issues:
            return StrengthResult("Weak", score, f"Missing: {', '.join(issues)}")

        suggestions = result["feedback"]["suggestions"]
        message = f"Password is {strength.lower()}."
        if suggestions:
            message += f" Suggestions: {', '.join(suggestions)}"

        return StrengthResult(strength, score, message)

    def generate_random_password(self, length=16):
        charset = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(charset) for _ in range(length))

    def suggest_improvements(self, password):
        result = self.check_password_strength(password)
        tips = []
        if len(password) < self.min_len:
            tips.append(f"Use at least {self.min_len} characters.")
        if not re.search(r'[A-Z]', password): tips.append("Add uppercase letters.")
        if not re.search(r'[a-z]', password): tips.append("Add lowercase letters.")
        if not re.search(r'\d', password): tips.append("Add numbers.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password): tips.append("Add symbols.")
        return "Suggestions:\n" + "\n".join(f"- {t}" for t in tips) if tips else result.message


class PasswordStrengthGUI:
    def __init__(self, root):
        self.ps = PasswordStrength()
        self.results = []

        root.title("Password Strength Checker")
        tk.Label(root, text="Enter Password:").pack()

        self.entry = tk.Entry(root, show="*")
        self.entry.pack()
        self.entry.bind("<Return>", lambda e: self.check())

        tk.Button(root, text="Check", command=self.check).pack()
        self.result_label = tk.Label(root, text="")
        self.result_label.pack()
        self.suggest_label = tk.Label(root, text="", fg="blue")
        self.suggest_label.pack()

        tk.Button(root, text="Generate Password", command=self.generate).pack()
        self.display = tk.Text(root, height=2, width=30)
        self.display.pack()
        tk.Button(root, text="Copy", command=self.copy).pack()
        tk.Button(root, text="Export Results", command=self.export).pack()
        tk.Button(root, text="Exit", command=root.quit).pack()

    def check(self):
        pwd = self.entry.get().strip()
        result = self.ps.check_password_strength(pwd)
        self.result_label.config(text=f"{result.strength}: {result.message}")
        self.suggest_label.config(text=self.ps.suggest_improvements(pwd))
        self.results.append({
            "password": pwd,
            "strength": result.strength,
            "message": result.message
        })

    def generate(self):
        pwd = self.ps.generate_random_password()
        self.entry.delete(0, tk.END)
        self.entry.insert(0, pwd)
        self.display.delete(1.0, tk.END)
        self.display.insert(tk.END, pwd)

    def copy(self):
        pwd = self.display.get(1.0, tk.END).strip()
        self.display.clipboard_clear()
        self.display.clipboard_append(pwd)
        messagebox.showinfo("Copied", "Password copied!")

    def export(self):
        if not self.results:
            messagebox.showerror("Error", "Nothing to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json")
        with open(path, "w") as f:
            json.dump(self.results, f, indent=4)
        messagebox.showinfo("Saved", f"Results saved to {path}")


class PasswordStrengthCLI:
    def __init__(self):
        self.ps = PasswordStrength()

    def check_password(self, password):
        result = self.ps.check_password_strength(password)
        print(f"\nStrength: {result.strength}")
        print(f"Message: {result.message}")
        print(self.ps.suggest_improvements(password))

    def generate_password(self, length=16):
        pwd = self.ps.generate_random_password(length)
        print(f"\nGenerated Password: {pwd}")
        self.check_password(pwd)


def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode")
    parser.add_argument("--check", type=str, help="Check provided password")
    parser.add_argument("--generate", action="store_true", help="Generate password")
    parser.add_argument("--length", type=int, default=16, help="Length for generation")

    args = parser.parse_args()

    if args.cli or args.check or args.generate:
        cli = PasswordStrengthCLI()
        if args.check:
            cli.check_password(args.check.strip())
        elif args.generate:
            cli.generate_password(args.length)
        elif args.cli:
            while True:
                print("\n========= PASSWORD CHECKER =========")
                print("1. Check Password Strength")
                print("2. Generate Strong Password")
                print("3. Exit")
                choice = input("Choose (1/2/3): ").strip()
                if choice == "1":
                    pwd = input("Enter password: ").strip()
                    cli.check_password(pwd)
                elif choice == "2":
                    try:
                        l = int(input("Length (default 16): ") or 16)
                        cli.generate_password(l)
                    except ValueError:
                        print("Invalid length. Using 16.")
                        cli.generate_password()
                elif choice == "3":
                    print("Bye!")
                    break
                else:
                    print("Invalid choice.")
    else:
        root = tk.Tk()
        PasswordStrengthGUI(root)
        root.mainloop()


if __name__ == "__main__":
    main()
