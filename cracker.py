import argparse
import hashlib
import itertools
import string
import threading
from queue import Queue
import time
import os

# ------------- HASHING FUNCTION -------------
def hash_string(text, algorithm='md5'):
    algo = algorithm.lower()
    h = None
    try:
        if algo == 'md5':
            h = hashlib.md5()
        elif algo == 'sha1':
            h = hashlib.sha1()
        elif algo == 'sha256':
            h = hashlib.sha256()
        else:
            raise ValueError("Unsupported hash type.")
        h.update(text.encode('utf-8'))
        return h.hexdigest()
    except Exception as e:
        print(f"Hashing error: {e}")
        return None

# ------------- DICTIONARY ATTACK -------------
def dictionary_attack(target_hash, algorithm, wordlist, result_found_flag):
    try:
        with open(wordlist, 'r', errors='ignore') as file:
            for line in file:
                if result_found_flag.is_set():
                    return
                word = line.strip()
                hashed = hash_string(word, algorithm)
                if hashed == target_hash:
                    print(f"\n[✔] Password found (Dictionary): {word}")
                    result_found_flag.set()
                    return
        print("\n[✘] Dictionary attack failed to find the password.")
    except FileNotFoundError:
        print("[!] Wordlist file not found.")
    except Exception as e:
        print(f"[!] Error in dictionary attack: {e}")

# ------------- BRUTE FORCE WORKER -------------
def brute_force_worker(queue, target_hash, algorithm, result_found_flag):
    while not queue.empty() and not result_found_flag.is_set():
        password = queue.get()
        hashed = hash_string(password, algorithm)
        if hashed == target_hash:
            print(f"\n[✔] Password found (Brute-force): {password}")
            result_found_flag.set()
        queue.task_done()

# ------------- GENERATE BRUTE FORCE COMBINATIONS -------------
def generate_passwords(min_len, max_len, charset):
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield ''.join(combo)

# ------------- MAIN CRACKER FUNCTION -------------
def password_cracker(args):
    target_hash = args.hash
    algorithm = args.algorithm.lower()
    wordlist = args.wordlist
    min_len = args.min
    max_len = args.max
    threads = args.threads

    print("[*] Starting password cracker...")
    print(f"[*] Target Hash: {target_hash}")
    print(f"[*] Hash Algorithm: {algorithm.upper()}")
    print(f"[*] Threads: {threads}\n")

    start_time = time.time()
    result_found_flag = threading.Event()

    if wordlist:
        print("[*] Running Dictionary Attack...")
        dictionary_attack(target_hash, algorithm, wordlist, result_found_flag)
    else:
        print("[*] Running Brute-force Attack...")
        charset = string.ascii_letters + string.digits
        queue = Queue()
        print("[*] Generating password combinations (this may take time)...")

        for password in generate_passwords(min_len, max_len, charset):
            queue.put(password)

        print(f"[*] Total combinations to try: {queue.qsize()}")
        thread_list = []
        for _ in range(threads):
            t = threading.Thread(target=brute_force_worker, args=(queue, target_hash, algorithm, result_found_flag))
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

        if not result_found_flag.is_set():
            print("\n[✘] Brute-force attack failed to find the password.")

    print(f"\n[✓] Execution Time: {round(time.time() - start_time, 2)} seconds")

# ------------- ENTRY POINT -------------
def main():
    parser = argparse.ArgumentParser(
        description="🔐 Password Cracker using Python.  --made the thekanhakodes:)\n\n"
                    "Crack a given hashed password using dictionary or brute-force techniques.\n"
                    "Supports MD5, SHA1, and SHA256 hashing algorithms.\n",
        epilog="""
Examples:

  Dictionary attack (using a wordlist):
    python cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5 --wordlist rockyou.txt

  Brute-force attack (auto-generating passwords):
    python cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5 --min 1 --max 4 --threads 8

Notes:
- The above hash is for the password 'password' using MD5.
- Wordlist files like rockyou.txt can be found on Kali Linux or online repositories.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--hash', required=True, help="Target hash value to crack (e.g., MD5/SHA1/SHA256 hash)")
    parser.add_argument('--algorithm', required=True, choices=['md5', 'sha1', 'sha256'],
                        help="Hashing algorithm used to generate the hash (md5, sha1, sha256)")
    parser.add_argument('--wordlist', help="Path to wordlist file for dictionary attack (optional)")
    parser.add_argument('--min', type=int, default=1, help="Minimum length of passwords for brute-force attack")
    parser.add_argument('--max', type=int, default=4, help="Maximum length of passwords for brute-force attack")
    parser.add_argument('--threads', type=int, default=4, help="Number of threads to use (default = 4)")

    args = parser.parse_args()
    password_cracker(args)

if __name__ == '__main__':
    main()
