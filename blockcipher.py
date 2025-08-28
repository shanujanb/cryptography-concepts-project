#Cryptographic Concepts - Assignment Part 1 
#Name = Shanujan Baskaran

# CONFIGURATION SECTION

BLOCK_SIZE_BYTES = 8  # I defined the block size as 8 bytes = 64 bits (Week 3 Slide 3)
KEY_SIZE_BYTES = 8    # The key size is also 8 bytes = 64 bits (Week 3 Slide 4)
NUM_ROUNDS = 10       # The cipher will run 10 rounds of substitution permutation 

# HELPER FUNCTIONS

def pad(data, block_size):
    # Adds padding to the data using PKCS#7 (Week 5 Slide 6)
    # This ensures the message length is a multiple of the block size
    padding_len = block_size - (len(data) % block_size)  # Calculates how many bytes are needed
    return data + bytes([padding_len] * padding_len)      # Adds as many bytes, each containing the value of padding length

def xor_bytes(a, b):
    # Performs XOR operation between two byte arrays (used for key addition and CBC chaining)
    # This is a basic operation in cryptography (Week 3 Slide 4)
    return bytes(x ^ y for x, y in zip(a, b))  # XOR each corresponding byte from a and b

def rotate_left(data_bytes, num_bits):
    # Rotates bits to the left (used in generating round keys)
    # This implements key scheduling (Week 3 Slide 6)
    num_bytes = len(data_bytes)
    if num_bytes == 0: return b''  # If input is empty, return empty bytes
    total_bits = num_bytes * 8      # Total number of bits to work with
    num_bits %= total_bits          # Prevent rotating more than the total number of bits
    if num_bits == 0: return data_bytes  # No rotation needed
    int_val = int.from_bytes(data_bytes, 'big')  # Convert byte data to a single integer 
    rotated_int = ((int_val << num_bits) | (int_val >> (total_bits - num_bits))) & ((1 << total_bits) - 1)  # Rotate left using bit manipulation
    return rotated_int.to_bytes(num_bytes, 'big')  # Convert back to bytes

# CIPHER BUILDING BLOCKS

def s_box(byte_val):
    # This is the Substitution Box (S-box) (Week 3 Slide 5)
    # It scrambles the input byte to hide patterns
    # NOTE: This is a simple LINEAR transformation chosen for educational purposes.
    # It is a significant security weakness vulnerable to linear cryptanalysis.
    # Secure ciphers use non-linear S-boxes for example lookup tables.
    return (byte_val * 5 + 123) % 256  # Simple math-based substitution

def apply_s_box(block):
    # Applies the S-box to every byte in the block (Week 3 Slide 5)
    return bytes(s_box(b) for b in block)  # Loop through block and apply s_box

def p_box(block):
    # This is the Permutation Box (P-box) (Week 3 Slide 6)
    # It rearranges the bytes to provide diffusion.
    # This is a fixed permutation: output indices correspond to input indices [7, 5, 3, 1, 6, 4, 2, 0]
    return bytes([block[7], block[5], block[3], block[1], block[6], block[4], block[2], block[0]])

def generate_round_keys(master_key):
    # Generates round keys by rotating the master key left by 8 bits each round (Week 3 Slide 6)
    # NOTE: This is a very simple key schedule based only on rotation (linear).
    # Securing ciphers using complex key schedules involving non-linear operations.
    if len(master_key) != KEY_SIZE_BYTES:
        raise ValueError(f"Key must be {KEY_SIZE_BYTES} bytes.")  # Ensure key is correct length
    round_keys = []                       # List to store all round keys
    current_key = master_key              # Start with master key
    # Generate NUM_ROUNDS keys for the rounds + 1 final key addition
    for _ in range(NUM_ROUNDS + 1):
        round_keys.append(current_key)  # Store current key
        current_key = rotate_left(current_key, 8)  # Rotate for next round key (linear operation)
    return round_keys

#  ENCRYPT A SINGLE BLOCK

def encrypt_block(block, master_key):
    # Encrypts a single block using all cipher steps: key addition, substitution, permutation (Week 3 Slides 4–6)
    if len(block) != BLOCK_SIZE_BYTES:
        raise ValueError("Internal error: encrypt_block requires 8-byte block.")  # Validate input size

    round_keys = generate_round_keys(master_key)  # Create round keys
    state = block                                 # Start with the plaintext block

    # Apply NUM_ROUNDS rounds of encryption
    for i in range(NUM_ROUNDS):
        state = xor_bytes(state, round_keys[i])   # Step 1: Add round key (key addition)
        state = apply_s_box(state)                # Step 2: Substitution
        state = p_box(state)                      # Step 3: Permutation

    # Final round key addition (no S-box or P-box in the final step as per common SPN structures)
    state = xor_bytes(state, round_keys[NUM_ROUNDS])
    return state  # Return encrypted block

# CBC MODE ENCRYPTION

def encrypt_message_cbc(message_str, key, iv):
    # Encrypts an entire message using CBC mode (Week 5 Slide 8–11)
    # CBC = Cipher Block Chaining, uses IV + previous ciphertext block

    if len(key) != KEY_SIZE_BYTES or len(iv) != BLOCK_SIZE_BYTES:
        raise ValueError(f"Key and IV must be {BLOCK_SIZE_BYTES} bytes.")  # Check key and IV sizes

    message_bytes = message_str.encode('utf-8')       # Convert input string to bytes
    padded_message = pad(message_bytes, BLOCK_SIZE_BYTES)  # Pad message (Week 5 Slide 6)

    ciphertext = b''                  # Final ciphertext starts empty
    previous_cipher_block = iv        # First block uses IV (initialization vector)

    # Process each block
    for i in range(0, len(padded_message), BLOCK_SIZE_BYTES):
        plaintext_block = padded_message[i : i + BLOCK_SIZE_BYTES]         # Extracts the next plaintext block
        block_to_encrypt = xor_bytes(plaintext_block, previous_cipher_block)  # XOR with previous cipher block (CBC Step)
        encrypted_block = encrypt_block(block_to_encrypt, key)            # Encrypts the block using our custom cipher
        ciphertext += encrypted_block                                     # Add result to ciphertext
        previous_cipher_block = encrypted_block                           # Update previous cipher block for next round

    return ciphertext  # Return final ciphertext

# MAIN EXECUTION

# This is the message we want to encrypt (assignment example)
message_X = "Transfer $571.99 from ABSecure Acc 12345 to Westpac Acc 135791 BSB 3344."

# 8-byte secret key for encryption (64-bit)
secret_key = b'examples'  # Make sure it's exactly 8 characters

# 8-byte Initialization Vector for CBC (64-bit)
initialization_vector = b'initialV'  # Make sure it's exactly 8 characters

# Print output
print(f"--- EduCipher Simple Encryption (CBC Mode) ---")
try:
    encrypted_output = encrypt_message_cbc(message_X, secret_key, initialization_vector)
    print(f"Original Message: {message_X}")
    print(f"Key (hex): {secret_key.hex()}")                  # Show key in hex format
    print(f"IV (hex):  {initialization_vector.hex()}")       # Show IV in hex
    print(f"Ciphertext (hex): {encrypted_output.hex()}")      # Show ciphertext in hex
except ValueError as e:
    print(f"Error: {e}")  # Print any key/IV length errors
except Exception as e:

    print(f"An unexpected error occurred: {e}")  # Catch-all for any other errors
