"""
This program implements 128-bit block cipher AES
Authors: Andrew McCuthan, Eleanor, Lam Do
Date: Februrary 5, 2026
CS402, Spring 2026
"""

import random
import message_tuple as mt

class AES:
    def __init__(self, key, message):
        self.key = key
        self.message = message
        self.sbox = self._create_sbox()
        
    def _create_sbox(self):
        """
        generates an S-Box that will be used for the substitute bytes step of encryption rounds
        """
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
        ["60","81","4F","DC","22","2A","90","88","46","EE","B8","14","DE","5E","0B","DB"],
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
        return sbox
    
    def _message_table(self, message):
        """Turns the initial message into a 4x4 table used for the rounds

        Args:
            message (string): original message to be encrypted

        Returns:
            list: a 2D array of our message with 8-bit index values.
        """
        table = [[], [], [], []]
        for i in range(0, len(message), 8):
            byte = message[i:i+8]
            row_index = i // 8 % 4
            table[row_index].append(byte)
        return table
    
    def _sub_bytes(self, message, sbox):
        """Substitution step of enctrpytion. Takes the original matrix and substitutes the bytes with our S-Box.

        Args:
            message (string): 4x4 Matrix table of message
            sbox (list): Our S-Box that will substitute the bytes

        Returns:
            list: 4x4 Matrix table of substiuted bits
        """
        output = []
        # Initilize new 128-bit message
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
    
    def _shift_rows(self, table):
        """Shifting the rows of our table 

        Args:
            table (list): 4X4 matrix array. This will be the state after the substitution step.

        Returns:
            list: 4x4 matrix array. New state with shifted rows.
        """
        shifted_table = []
        for i in range(4):
            if i == 0:
                shifted_table.append(table[i]) # First row is not shifted
            elif i == 1:
                shifted_table.append(table[i][1:] + table[i][:1]) # Second row is shifted left by 1
            elif i == 2:
                shifted_table.append(table[i][2:] + table[i][:2]) # Third row is shifted left by 2
            elif i == 3:
                shifted_table.append(table[i][3:] + table[i][:3]) # You get the idea
        return shifted_table
    
    def _mix_columns(self, state):
        """This is performing the Mix column step of AES using GF multiplication.

        Args:
            state (list): 4x4 matrix array. 

        Returns:
            _type_: _description_
        """
        for i in range(4):
            # Convert binary strings to integers
            s0 = int(state[0][i], 2)
            s1 = int(state[1][i], 2)
            s2 = int(state[2][i], 2)
            s3 = int(state[3][i], 2)

            # Perform the MixColumns transformation using Galois Field multiplication
            s0 = (self._times_two(s0) ^ self._times_three(s1) ^ s2 ^ s3) & 0xff
            s1 = (s0 ^ self._times_two(s1) ^ self._times_three(s2) ^ s3) & 0xff
            s2 = (s0 ^ s1 ^ self._times_two(s2) ^ self._times_three(s3)) & 0xff
            s3 = (self._times_three(s0) ^ s1 ^ s2 ^ self._times_two(s3)) & 0xff

            # Convert integers back to binary strings and update state (zfill pads with 0's to get 8-bit string)
            state[0][i] = bin(s0)[2:].zfill(8)
            state[1][i] = bin(s1)[2:].zfill(8)
            state[2][i] = bin(s2)[2:].zfill(8)
            state[3][i] = bin(s3)[2:].zfill(8)
        return state
            
    def _times_two(self, byte):
        if byte & 0x80:
            return ((byte << 1) ^ 0x1b) & 0xff
        else:
            return (byte << 1) & 0xff

    def _times_three(self, byte):
        return self._times_two(byte) ^ byte
    
    def _add_round_key(self, state, round_key):
        for row in range(4):
            for col in range(4):
                state[row][col] = bin(int(state[row][col], 2) ^ int(round_key[row][col], 2))[2:].zfill(8)
        return state
        
    
    def _key_expansion(self, key):
        """
        Input: 128-bit key
        Output: Array w of 44 words
        """
        # Pull values from textbook
        Rcon_hex = ["00", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36"]
        Rcon = [bin(int(hex,16))[2:].zfill(8) + "0" * 24 for hex in Rcon_hex]

        # Initialize array w of 44 words
        w = [None] * 44
        # Step 1: Copy key to the first 4 words of w array
        for i in range(4):
            w[i] = key[i* 32 : i*32 + 32]
        # Step 2: Fill in the rest of w array
        for i in range(4, 44):
            temp = w[i-1]
            if i % 4 == 0:
                temp = self._xor(self._sub_word(self._rot_word(temp)), Rcon[i//4])
            w[i] = self._xor(w[i-4], temp)
        return w
    
    def _xor(self, string1, string2):
        """
        This function performs a bitwise XOR operation on string1 and string2
        Input: 2 strings of binary bits
        Output: XOR string of string1 and string2
        """
        xor_result = int(string1, 2) ^ int(string2, 2)
        xor_string = bin(xor_result)[2:]
        output = xor_string.zfill(len(string1))
        return output
    
    def _sub_word(self, word):
        """
        This function performs byte substitution via S-box
        Input: 4-byte word
        Output: 4-byte word 
        """
        output = ""
        for i in range(0, 32, 8):
            byte = word[i:i+8]
            row = int(byte[:4], 2)
            col = int(byte[4:], 2)
            output = output + self.sbox[row][col] 
        return output

    def _rot_word(self, word):
        """
        This function performs one-byte left shift [B0, B1, B2, B3] -> [B1, B2, B3, B0]
        Input: 4-byte word
        Output 4-byte word
        """
        return word[8:] + word[:8]
    
    def encrypt(self, key, message):
        # Prepare state and round keys
        matrix_table = self._message_table(message)
        sbox = self._create_sbox()
        expanded_key = self._key_expansion(key)

        # Build 11 round keys (each round key is 4 words -> 4x4 matrix of bytes)
        round_keys = []
        for r in range(11):
            words = expanded_key[r*4:(r+1)*4]
            round_key = [[None for _ in range(4)] for _ in range(4)]
            for c in range(4):
                word = words[c]
                for row in range(4):
                    round_key[row][c] = word[row*8:(row+1)*8]
            round_keys.append(round_key)

        # Initial AddRoundKey
        state = self._add_round_key(matrix_table, round_keys[0])

        # Rounds 1..9
        for r in range(1, 10):
            state = self._sub_bytes(state, sbox)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, round_keys[r])
            print("This is state after round " + str(r) + ":" + str(state))

        # Final round (no MixColumns)
        state = self._sub_bytes(state, sbox)
        state = self._shift_rows(state)
        state = self._add_round_key(state, round_keys[10])

        return state
        

def main():
    key = bin(mt.key)[2:].zfill(128)
    cipher = AES(key, mt.message)
    
    print("Key:", key)
    print(f"Message: {mt.message}\n")

    encrypted_message = cipher.encrypt(cipher.key, cipher.message)
    print("Original Message:")
    message_block = cipher._message_table(cipher.message)
    for row in message_block:
        print(row)  
    print()
    print("Encrypted Message Table:")
    for row in encrypted_message:
        print(row)  
    print()
        
    encrypted_message = cipher.encrypt(cipher.key, cipher.message)
    
    ciphertext = ""
    for row in encrypted_message:
        for byte in row:
            byte_int = int(byte, 2)
            byte_hex = hex(byte_int)[2:].zfill(2)
            ciphertext += byte_hex
    print("Ciphertext:", ciphertext)
        
            
    
    # cipher_table = cipher.message_table(cipher.message)
    # print("Cipher Table:")
    # print(cipher_table)
    # shifted_table = cipher.shift_rows(cipher_table)
    # print("Shifted Table:")
    # print(shifted_table)
    
if __name__ == "__main__":
    main()



