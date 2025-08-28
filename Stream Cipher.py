#Cryptographic Concepts - Assignment Part 1 
#Saneth Fernando - 10696577
#Enhanced Stream Cipher for ABSecure

#When prompted, enter a numeric key (e.g.123456) and press Enter.

# LCG constants for large period
A = 1103515245  # multiplier
C = 12345       # increment
M = 2**64       # modulus (64-bit state)

#LFSR constants for 32-bit register
LFSR_SIZE = 32
LFSR_TAPS = [31, 29, 25, 24]  
MAX_LFSR = 2**LFSR_SIZE - 1   #Max period: 2^32 - 1
WARMUP = 1024                 # Warmup iterations for state mixing

# Sample message with case, numerals, and punctuation
MESSAGE = "Transfer $571.99 from ABSecure Acc 12345 to Westpac Acc 135791 BSB 3344."

def lfsr(state):
    #Performs one LFSR step: shift left, XOR feedback from taps.
    feedback = 0
    for tap in LFSR_TAPS:  #Compute feedback by XORing tapped bits
        feedback ^= (state >> tap) & 1
    return ((state << 1) & MAX_LFSR) | feedback  #Shift and add feedback bit

def hybrid_prng(key, iv, length):
    #Generate a keystream using a hybrid LCG + LFSR PRNG.
    #Arguments used:
        #key: 32-bit integer key
        #iv: 32-bit initialization vector
        #length: Number of bytes needed
    #Returns: List of pseudo-random bytes.
    keystream = []
    lcg_state = (key << 32) | iv  # Combine key and IV for 64-bit LCG seed
    lfsr_state = iv & MAX_LFSR    # Seed LFSR with IV (32-bit mask)
    
    #Warmup phase: Mix state for 1024 iterations
    for _ in range(WARMUP):
        lcg_state = (A * lcg_state + C) % M  #Update LCG
        lfsr_state = lfsr(lfsr_state)        #Update LFSR
    
    #Generates keystream bytes
    for _ in range(length):
        lcg_state = (A * lcg_state + C) % M  # Next LCG value
        lfsr_state = lfsr(lfsr_state)        # Next LFSR value
        # Non-linear mixing: (XOR and AND outputs for randomness)
        mixed = (lcg_state & 0xFF) ^ (lfsr_state & 0xFF) ^ ((lcg_state >> 8) & (lfsr_state >> 8))
        keystream.append(mixed % 256)  # Ensures the byte range (0-255)
    return keystream

def encrypt(plaintext, key, iv):
    #Encrypt plaintext by XORing with PRNG keystream.
    keystream = hybrid_prng(key, iv, len(plaintext))  # Match keystream to message length
    return "".join(chr(ord(p) ^ k) for p, k in zip(plaintext, keystream))  #XOR each char

def decrypt(ciphertext, key, iv):
     #decrypt ciphertext (same as encrypt due to XOR symmetry).
    return encrypt(ciphertext, key, iv)  #Reuses encrypt function

def to_hex(data):
    #Convert string to hexadecimal for readable output.
    return data.encode("utf-8").hex()

if __name__ == "__main__":
    # Display welcome message and instructions
    print("Welcome to ABSecure Enhanced Stream Cipher")
    print("Follow the prompts to encrypt and decrypt a sample message.\n")
    
    # Prompt user for key and IV, with examples
    key = int(input("Enter a numeric key (e.g., 123456): ")) & 0xFFFFFFFF  #32-bit mask
    iv = int(input("Enter a numeric IV (e.g., 654321): ")) & 0xFFFFFFFF    #32-bit mask
    
    # Show original message
    print("\nOriginal Message:", MESSAGE)
    
    #Encrypt and display results
    encrypted = encrypt(MESSAGE, key, iv)
    print("\nEncrypted Message (non-readable):", repr(encrypted))  # Raw string
    print("\nEncrypted Message (Hex):", to_hex(encrypted))        #Hex format
    
    #Decrypt and verify
    decrypted = decrypt(encrypted, key, iv)
    print("\nDecrypted Message:", decrypted)

