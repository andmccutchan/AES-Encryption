import project1_part1 as p1
import message_tuple as mt
import random

mode_of_operation = "ECB"

def ecb(message, key):
    ciphertext = "" 
    for i in range(0, len(message), 128): 
        if i+128 > len(message):
            block = message[i:] + ' ' * (128 - (len(message) - i))
        else:
            block = message[i:i+128]
        aes_cipher = p1.AES(key, block)
        cipherblock = aes_cipher.encrypt(key, block)
        # Flatten the 4x4 matrix to a string
        cipherblock_str = ''.join(''.join(row) for row in cipherblock)
        ciphertext += cipherblock_str
    return ciphertext

def ctr(message, key):
    ciphertext = ""
    random.seed(mt.seed)  # Ensure the same random sequence for reproducibility
    counter = random.getrandbits(128)  # Initialize counter with a random 128-bit value
    for i in range(0, len(message), 128):
        if i+128 > len(message):
            block = message[i:] + ' ' * (128 - (len(message) - i))
        else:
            block = message[i:i+128]
        counter_str = format(counter, '0128b')  # Convert counter to 128-bit binary string
        aes_cipher = p1.AES(key, counter_str)
        cipher_ctr_matrix = aes_cipher.encrypt(key, counter_str)
        # Flatten the 4x4 matrix to a string
        cipher_ctr = ''.join(''.join(row) for row in cipher_ctr_matrix)
        if len(cipher_ctr) > len(block):
            cipher_ctr = cipher_ctr[:len(block)]
        # XOR the encrypted counter with the plaintext block
        cipherblock = ''.join(str(int(cipher_ctr[j]) ^ int(block[j])) for j in range(len(block)))
        ciphertext += cipherblock
        counter += 1
    return ciphertext 

def change_mode(new_mode):
    global mode_of_operation
    if new_mode in ["ECB", "CTR"]:
        mode_of_operation = new_mode
    else:
        print("Invalid mode. Please choose 'ECB' or 'CTR'.")

def main(): 
    # Get key from message_tuple file that initializes it
    key = mt.key
    message_text = "All Denison students should take" # First 256 bits of the message "All Denison students should take CS402!"
    message = mt.text_to_bits(message_text)[:128]  # Convert to binary and use first 128 bits

    # Get user input for mode of operation
    user_input = input("Enter mode of operation (ECB/CTR): ")
    change_mode(user_input)

    # Encrypt the message using the mode of operation specified in the global variable
    if mode_of_operation == "ECB":
        ciphertext = ecb(message, key)
        print(f"ECB Ciphertext: {ciphertext}")
    elif mode_of_operation == "CTR":
        ciphertext = ctr(message, key)
        print(f"CTR Ciphertext: {ciphertext}")
    else:
        print("Invalid mode of operation. Please choose 'ECB' or 'CTR'.")
if __name__ == "__main__":
    main()