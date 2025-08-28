# Cryptographic Concepts Project – Custom Stream & Block Cipher (Python)

This repository contains a project completed for the **Cryptographic Concepts** course in 2025.  
It was a team assignment (2 members) where we designed and implemented cryptographic systems in Python.  
Final Grade: **32/35** ✅

---

## 🔐 Features

### 1. Hybrid PRNG (Pseudo-Random Number Generator)
- Combines **Linear Congruential Generator (LCG)** and **Linear Feedback Shift Register (LFSR)**.
- Non-linear mixing increases randomness.
- Includes a 1024-iteration warm-up phase for state mixing.

### 2. Enhanced Stream Cipher
- Uses the hybrid PRNG to generate keystreams.
- Encrypts/decrypts messages via XOR (symmetric process).
- Demonstrated with short financial transactions.

### 3. EduCipher – Custom Block Cipher
- Based on **Substitution–Permutation Network (SPN)** design.
- 64-bit block size, 10 encryption rounds.
- Simple S-box (linear function) and fixed P-box for diffusion.
- Implemented in **CBC (Cipher Block Chaining)** mode with PKCS#7 padding.

### 4. Security Analysis
- Identified strengths & weaknesses of both stream and block cipher designs.
- Issues: Predictable LFSR, linear S-box vulnerability.
- Proposed improvements:
  - Replace linear S-box with non-linear (AES-style).
  - Add **Message Authentication Code (MAC)** for integrity.
  - Increase block/key sizes for modern standards.

---

## 📂 Files
- `stream_cipher.py` → Hybrid PRNG + Stream Cipher implementation.
- `educipher.py` → Block Cipher (EduCipher) with CBC mode.

---

## 🛡️ Key Learnings
- How pseudo-random number generators (PRNGs) are used in cryptography.
- Practical implementation of **stream ciphers** and **block ciphers**.
- Importance of design choices (non-linearity, key schedule, diffusion).
- How to perform **cryptographic strength analysis** and propose improvements.



