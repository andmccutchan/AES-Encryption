import project1_part1 as p1
import message_tuple as mt
import random

mode_of_operation = "ECB"

def ecb(message, key):
    ciphertext = "" 
    for i in range(0, len(message), 16): 
        if i+16 > len(message):
            block = message[i:] + ' ' * (16 - (len(message) - i))
        else:
            block = message[i:i+16]
        cipherblock = p1.AES(key, block).encrypt(key, block)
        ciphertext += cipherblock
    return ciphertext

def ctr(message, key):
    ciphertext = ""
    random.seed(mt.seed)  # Ensure the same random sequence for reproducibility
    counter = random.getrandbits(128)  # Initialize counter with a random 128-bit value
    for i in range(0, len(message), 16):
        if i+16 > len(message):
            block = message[i:] + ' ' * (16 - (len(message) - i))
        else:
            block = message[i:i+16]
        cipher_ctr = p1.AES(key, str(counter)).encrypt(key, str(counter))
        if len(cipher_ctr) > len(block):
            cipher_ctr = cipher_ctr[:len(block)]
        cipherblock = int(cipher_ctr) ^ int(block)
        ciphertext += cipherblock
        counter += 1 

def change_mode(new_mode):
    global mode_of_operation
    if new_mode in ["ECB", "CTR"]:
        mode_of_operation = new_mode
    else:
        print("Invalid mode. Please choose 'ECB' or 'CTR'.")

def main(): 
    # Get key from message_tuple file that initializes it
    key = mt.key
    message =  "All Denison students should take" # First 256 bits of the message "All Denison students should take CS402!"

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

