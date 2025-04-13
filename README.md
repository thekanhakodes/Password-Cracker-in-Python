# 🔐 Password Cracker in Python

A command-line tool to crack hashed passwords using either dictionary attacks or brute-force techniques. It supports MD5, SHA1, and SHA256 hashing algorithms and utilizes multi-threading to accelerate the cracking process.

---

## 🚀 Features
- Supports **MD5**, **SHA1**, and **SHA256** hashing algorithms
- **Dictionary attack** using common password lists
- **Brute-force attack** with customizable length and characters
- **Multi-threaded** processing for faster execution
- Simple and well-documented **command-line interface**

---

## 📦 Requirements
- Python 3.x

No external libraries are required. All dependencies are standard Python modules.

---

## ⚙️ Usage

### 📘 Dictionary Attack
Use a wordlist (like `rockyou.txt`) to guess the password:
```bash
python cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5 --wordlist rockyou.txt
```

### 🧠 Brute Force Attack
Try all combinations within a specified length range:
```bash
python cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5 --min 1 --max 4 --threads 6
```

---

## 📝 Arguments
| Argument      | Required | Description |
|---------------|----------|-------------|
| `--hash`      | ✅ Yes   | The hash you want to crack |
| `--algorithm` | ✅ Yes   | Hashing algorithm (`md5`, `sha1`, `sha256`) |
| `--wordlist`  | ❌ No    | Path to wordlist file for dictionary attack |
| `--min`       | ❌ No    | Minimum password length (for brute-force) |
| `--max`       | ❌ No    | Maximum password length (for brute-force) |
| `--threads`   | ❌ No    | Number of threads to use (default is 4) |

---

## 🧪 Examples
```bash
# Example 1: Crack MD5 hash using a wordlist
python cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5 --wordlist passwords.txt

# Example 2: Brute-force attack with 6 threads, length 1 to 4
python cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5 --min 1 --max 4 --threads 6
```

---

## 📚 Notes
- The hash `5f4dcc3b5aa765d61d8327deb882cf99` corresponds to the password `password` using MD5.
- Common wordlists can be found on platforms like [SecLists](https://github.com/danielmiessler/SecLists) or are pre-installed in tools like Kali Linux.

---

## 🧠 Learning Outcomes
- Understand how password hashes can be cracked
- Learn about Python threading and cryptographic libraries
- Gain hands-on experience in cybersecurity and ethical hacking

---

## 🛡️ Disclaimer
This tool is intended for **educational** and **ethical use only**. Do not use it on systems without proper authorization.

---

## 📜 LICENSE (MIT)
---------------------------
This project is licensed under the **MIT License** — feel free to use, modify, or fork with credit.

---

## 👨‍💻 Author
Crafted and customized for internship and cybersecurity training. If you use this in a portfolio, make sure you understand every line — it's built for learning.
