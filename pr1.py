import random
import secrets

""" 
k = 8 bit key
func = bool, true = encrypy | false = decrypt
m = message to decrypt or encrypt
"""
oracle_table = {}

def oracle(k, func, m):
    if k not in oracle_table:
        oracle_table[k] = {}
    
    if (func, m) in oracle_table[k]:
        return oracle_table[k][(func, m)]
    
    used_values = set(oracle_table[k].values())
    
    while True:
        rand_value = random.randint(0, 255)
        if rand_value not in used_values:
            break
    
    oracle_table[k][(func, m)] = rand_value
    oracle_table[k][(not func, rand_value)] = m
    
    return rand_value
            
def main():
    key = 42
    plaintext = 99
    ciphertext = oracle(key, True, plaintext)
    decrypted = oracle(key, False, ciphertext)
    print(f"plaintext -> {plaintext}")
    print(f"ciphertext -> {ciphertext}")
    print(f"Decrpyted text -> {decrypted}")
if __name__ == "__main__":
    main()