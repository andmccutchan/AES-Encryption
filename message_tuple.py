import random

seed = 1965708
random.seed(seed)

key = random.getrandbits(128)
print(f"Key:", key)

def text_to_bits(text: str, encoding="utf-8") -> str:
    data = text.encode(encoding)
    return ''.join(f'{byte:08b}' for byte in data)

message = text_to_bits("D01965708D01966276D01975251")[:128]




