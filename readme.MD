
# 🔐 Pinnacle Lab Internship Tasks

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Made with ❤️ by Abhijith](https://img.shields.io/badge/Made%20with-%E2%9D%A4-red)](https://github.com/abhijithmr226)

This repository showcases key Python-based projects developed during the **Pinnacle Lab Cybersecurity Internship**, focusing on:

- ✅ Password Strength Analysis  
- 🔐 Text Encryption with AES, DES, RSA  
- 🎯 Keylogger with file-based export

---

## 📁 Project Structure

```bash
Pinnacle_Lab/
├── Keylogger_Software/
│   ├── keylogger.py             # Keylogger script
│   └── keylog.txt               # Keystroke logs
│
├── Password_Analyzer/
│   ├── analyzer.py              # Strength analyzer
│   ├── banned_password.txt      # Common banned passwords
│   ├── password_checker.log     # Log file
│   └── weak_passwords.txt       # Weak password output
│
├── Text_Encryption/
│   └── encryptor.py             # RSA, AES, DES unified script
└── README.md
```

---

## 🔑 Password Analyzer

### 🚀 Features:
- Password strength rating
- Checks for weak/banned entries
- Logs results to `password_checker.log`
- Outputs weak passwords for auditing

### ▶️ Run:
```bash
cd Password_Analyzer
python analyzer.py yourpassword123
```

---

## 🔐 Text Encryption (RSA, AES, DES)

A single Python script supports all three major encryption techniques.

### 🔒 Features:
- Encrypt/Decrypt text input using:
  - AES (Symmetric)
  - DES (Symmetric)
  - RSA (Asymmetric)
- Includes key generation (for RSA)

### ▶️ Run:
```bash
cd Text_Encryption
python encryptor.py
```

Follow the menu to select encryption type.

---

## 🛡️ Keylogger Software

> ⚠️ **Ethical use only** — for educational/research purposes. Never use without user consent.

### 🧠 Features:
- Captures all keyboard input
- Logs to `keylog.txt`
- Runs silently in the background

### ▶️ Run:
```bash
cd Keylogger_Software
python keylogger.py
```

Check `keylog.txt` for captured logs.

---

## 📦 Requirements

Install required libraries:

```bash
pip install pycryptodome pynput
```

---

## 📜 Disclaimer

> This repository is intended solely for **educational and ethical** cybersecurity learning. Unauthorized use of these tools is strictly prohibited.

---

## 👨‍💻 Author

**Abhijith M.R.**  
📧 [abhijhithmr226@gmail.com](mailto:abhijhithmr226@gmail.com)  
🌐 [GitHub](https://github.com/abhijithmr226) | [Instagram](https://instagram.com/abhiz.me) | [LinkedIn](https://linkedin.com/in/abhijith226linkedin)

---

## 📄 License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT) © 2025 Abhijith M.R.
