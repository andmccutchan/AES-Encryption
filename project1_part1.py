import random

seed = 01975251
random.seed(seed)

key = random.getrandbits(128)

def text_to_bits(text: str, encoding="utf-8") -> str:
    data = text.encode(encoding)
    return ''.join(f'{byte:08b}' for byte in data)


