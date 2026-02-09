import random

seed = 1965708
random.seed(seed)

key = format(random.getrandbits(128), '0128b')  # Convert to 128-bit binary string

def text_to_bits(text: str, encoding="utf-8") -> str:
    data = text.encode(encoding)
    return ''.join(f'{byte:08b}' for byte in data)

plaintext = "D01965708D01966276D01975251"
message = text_to_bits(plaintext)[:128]




