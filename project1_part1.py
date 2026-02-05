"""
This program implements 128-bit block cipher AES
Authors: Andrew McCuthan, Eleanor, Lam Do
Date: Februrary 5, 2026
CS402, Spring 2026
"""

import random

seed = 1965708
random.seed(seed)

key = random.getrandbits(128)

def text_to_bits(text: str, encoding="utf-8") -> str:
    data = text.encode(encoding)
    return ''.join(f'{byte:08b}' for byte in data)

message = text_to_bits("D01965708D01966276D01975251")[:128]
encrypt_input = (key, message)

print(encrypt_input)

# SubBytes implementation

# 1. Set up S Box
sbox = [
    ["63","7C","77","7B","F2","6B","6F","C5","30","01","67","2B","FE","D7","AB","76"],
    ["CA","82","C9","7D","FA","59","47","F0","AD","D4","A2","AF","9C","A4","72","C0"],
    ["B7","FD","93","26","36","3F","F7","CC","34","A5","E5","F1","71","D8","31","15"],
    ["04","C7","23","C3","18","96","05","9A","07","12","80","E2","EB","27","B2","75"],
    ["09","83","2C","1A","1B","6E","5A","A0","52","3B","D6","B3","29","E3","2F","84"],
    ["53","D1","00","ED","20","FC","B1","5B","6A","CB","BE","39","4A","4C","58","CF"],
    ["D0","EF","AA","FB","43","4D","33","85","45","F9","02","7F","50","3C","9F","A8"],
    ["51","A3","40","8F","92","9D","38","F5","BC","B6","DA","21","10","FF","F3","D2"],
    ["CD","0C","13","EC","5F","97","44","17","C4","A7","7E","3D","64","5D","19","73"],
    ["60","81","4F","DC","22","2A","90","8888","46","EE","B8","14","DE","5E","0B","DB"],
    ["E0","32","3A","0A","49","06","24","5C","C2","D3","AC","62","91","95","E4","79"],
    ["E7","C8","37","6D","8D","D5","4E","A9","6C","56","F4","EA","65","7A","AE","08"],
    ["BA","78","25","2E","1C","A6","B4","C6","E8","DD","74","1F","4B","BD","8B","8A"],
    ["70","3E","B5","66","48","03","F6","0E","61","35","57","B9","86","C1","1D","9E"],
    ["E1","F8","98","11","69","D9","8E","94","9B","1E","87","E9","CE","55","28","DF"],
    ["8C","A1","89","0D","BF","E6","42","68","41","99","2D","0F","B0","54","BB","16"],
]

for row in range(16):
    for col in range(16):
        # Convert hexadecimal values to binary 8-bit values
        hex = sbox[row][col]
        dec = int(hex, 16)
        binary = str(bin(dec)[2:])

        # Pad binary value with 0's to get 8-bit string
        binary_str = binary.zfill(8)
        sbox[row][col] = binary_str

# 2. One to One mapping via S-box
def subBytes(message, sbox):
    """
    Input: 128-bit message, represented as 4x4 array that stores 8-bit values
    Output: 128-bit message, represented as 4x4 array that stores 8-bit values
    """
    output = []
    # Initiliate new 128-bit message
    for row in range(4):
        output.append([0 for col in range(4)])

    # One to one mapping via S-box
    for row in range(4):
        for col in range(4):
            byte = message[row][col]
            # First 4 bits represent row index
            sbox_row = int(byte[:4], 2)
            # Last 4 bits represent column index
            sbox_col = int(byte[4:], 2)
            output[row][col] = sbox[sbox_row][sbox_col]
    return output

""" Testing block for SubBytes
test_input = [
    ["10101100", "00111001", "11100010", "01010111"],
    ["00011101", "11001010", "01100100", "10011011"],
    ["11110000", "01001101", "00101010", "10100001"],
    ["01111110", "00000111", "11010100", "10001100"],
]

print(subBytes(test_input, sbox))
"""








