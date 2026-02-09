"""
This program generates a random 128-bit key and a 128-bit message
Authors: Andrew McCuthan, Eleanor, Lam Do
Date: Februrary 5, 2026
CS402, Spring 2026
"""
import random

# Set a fixed seed for reproducibility
seed = 1965708
random.seed(seed)

def text_to_bits(text: str, encoding="utf-8") -> str:
    data = text.encode(encoding)
    return ''.join(f'{byte:08b}' for byte in data)

# Generate a random 128-bit key (16 bytes) and message (16 bytes)
key = format(random.getrandbits(128), '0128b')  
message = text_to_bits("D01965708D01966276D01975251")[:128]




