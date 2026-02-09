"""
This program implements AES encryption in ECB and CTR modes of operation. 
Authors: Andrew McCuthan, Eleanor, Lam Do
Date: Februrary 5, 2026
CS402, Spring 2026
"""

import project1_part1 as p1
import message_tuple as mt
import random

mode_of_operation = "ECB"

def ecb(message, key):
    """Encrypts the message using AES encryption in ECB mode

    Parameters:
        message (string): The plaintext message to be encrypted
        key (string): The 128-bit key for encryption

    Returns:
        string: The resulting ciphertext after encryption in ECB mode
    """
    # Initialize empty ciphertext string
    ciphertext = "" 
    # Process the message in 128-bit (16-byte) blocks
    for i in range(0, len(message), 128): 
        # If the last block is less than 128 bits, pad it with spaces to make it 128 bits
        if i+16 > len(message):
            block = message[i:] + ' ' * (128 - (len(message) - i))
        else:
            block = message[i:i+128]
        # Encrypt the block using AES encryption
        cipherblock = p1.AES().encrypt(key, block)
        # Append the resulting ciphertext block to the end of the ciphertext string
        ciphertext += cipherblock
    return ciphertext

def ctr(message, key):
    """Encrypts the message using AES encryption in CTR mode

    Parameters:
        message (string): The plaintext message to be encrypted
        key (string): The 128-bit key for encryption

    Returns:
        string: The resulting ciphertext after encryption in CTR mode
    """
    # Initialize empty ciphertext string
    ciphertext = ""
    # Ensure the same random sequence for reproducibility
    random.seed(mt.seed) 
    # Initialize counter with a random 128-bit value
    counter = format(random.getrandbits(128), '0128b')

    # Process the message in 128-bit (16-byte) blocks
    for i in range(0, len(message), 128):
        # If the last block is less than 128 bits, take the remaining bits as the block
        if i+128 > len(message):
            block = message[i:]
        else:
            block = message[i:i+128]

        # Encrypt the counter value using AES encryption 
        cipher_ctr = p1.AES().encrypt(key, counter)

        # If the last block is less than 128 bits, cut off extra bits from encrypted counter
        if len(cipher_ctr) > len(block):
            cipher_ctr = cipher_ctr[:len(block)]

        # XOR the encrypted counter with the plaintext block to get the ciphertext block
        cipherblock = int(cipher_ctr, 2) ^ int(block, 2)
        ciphertext += bin(cipherblock)[2:].zfill(len(block))

        # Increment the counter for the next block
        counter_int = int(counter, 2) + 1
        counter = format(counter_int, '0128b')
    return ciphertext

def change_mode(new_mode):
    global mode_of_operation
    if new_mode in ["ECB", "CTR"]:
        mode_of_operation = new_mode
    else:
        print("Invalid mode. Please choose 'ECB' or 'CTR'.")

def main(): 
    # Get key and message
    key = mt.key
    plaintext =  "All Denison students should take CS402!" 
    message = mt.text_to_bits(plaintext)[:256]  

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
