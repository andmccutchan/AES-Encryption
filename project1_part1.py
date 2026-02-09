"""
This program implements 128-bit block cipher AES
Authors: Andrew McCuthan, Eleanor, Lam Do
Date: Februrary 5, 2026
CS402, Spring 2026
"""
import message_tuple as mt

class AES:
    def __init__(self):
        """Initializes the AES cipher and create S-Box
        """
        self.sbox = self._create_sbox()
        
    def _create_sbox(self):
        """Generates an S-box for nonlinear substitution
        
        Parameters: None

        Returns: 
            list: S-box as a 2D array of binary strings (16x16 matrix of 8-bit binary strings)
        """
        # S-box values from textbook (hexadecimal)
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
        # Convert hexadecimal S-box to binary S-box
        for row in range(16):
            for col in range(16):
                hex = sbox[row][col]
                dec = int(hex, 16)
                binary = str(bin(dec)[2:])

                # Pad binary value with 0's to get 8-bit string
                binary_str = binary.zfill(8)
                sbox[row][col] = binary_str
        return sbox
    
    def _message_table(self, message):
        """Turns the initial message into a 4x4 table used for the rounds

        Parameters:
            message (string): original message to be encrypted

        Returns:
            list: a 2D (4x4) array of our message with 8-bit index values.
        """
        # Initialize empty 4x4 table
        table = [[], [], [], []]
        # Fill in the table column by column with 8-bit segments of the message
        for i in range(0, len(message), 8):
            byte = message[i:i+8]
            row_index = i // 8 % 4
            table[row_index].append(byte)
        return table
    
    def _sub_bytes(self, message):
        """Substitution step of encryption. Takes the original matrix and substitutes the bytes with our S-Box.
        
        Parameters:
            message (string): 4x4 Matrix table of message
            sbox (list): Our S-Box that will substitute the bytes

        Returns:
            list: 4x4 Matrix table of substituted bits
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
                output[row][col] = self.sbox[sbox_row][sbox_col]
        return output
    
    def _shift_rows(self, table):
        """Shifts the rows of our table 

        Parameters:
            table (list): 4X4 matrix array. This will be the state after the substitution step.

        Returns:
            list: 4x4 matrix array. New state with shifted rows.
        """
        shifted_table = []
        for i in range(4):
            # First row is not shifted
            if i == 0:
                shifted_table.append(table[i])    
            # Second row is shifted left by 1                  
            elif i == 1:
                shifted_table.append(table[i][1:] + table[i][:1])   
            # Third row is shifted left by 2
            elif i == 2:
                shifted_table.append(table[i][2:] + table[i][:2])   
            # You get the idea
            elif i == 3:
                shifted_table.append(table[i][3:] + table[i][:3])   
        return shifted_table
    
    def _mix_columns(self, state):
        """Performs the Mix column step of AES using GF multiplication.

        Parameters:
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
        """Generates the round keys for AES encryption using the key expansion algorithm
        
        Parameters:
            key (string): 128-bit key for encryption

        Returns:
            list: An array of 44 words (each word is 32 bits)
        """
        # Rcon values from textbook (hexadecimal)
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
        """Performs a bitwise XOR operation on two binary strings

        Parameters:
            string1 (string): First binary string
            string2 (string): Second binary string

        Returns:
            string: Result of XOR operation as a binary string
        """
        xor_result = int(string1, 2) ^ int(string2, 2)
        xor_string = bin(xor_result)[2:]
        output = xor_string.zfill(len(string1))
        return output
    
    def _sub_word(self, word):
        """Performs byte substitution on a 4-byte word using the S-box
        
        Parameters:
            word (string): 4-byte word (32 bits) to be substituted

        Returns:
            string: Substituted 4-byte word (32 bits) after applying S-box
        """
        output = ""
        for i in range(0, 32, 8):
            byte = word[i:i+8]
            row = int(byte[:4], 2)
            col = int(byte[4:], 2)
            output = output + self.sbox[row][col] 
        return output

    def _rot_word(self, word):
        """Performs one-byte left shift [B0, B1, B2, B3] -> [B1, B2, B3, B0]

        Parameters:
            word (string): 4-byte word (32 bits) to be rotated
        
        Returns:
            string: Rotated 4-byte word (32 bits) after left shift
        """
        return word[8:] + word[:8]
    
    def encrypt(self, key, message):
        """Encrypts the message using the AES encryption algorithm with the provided key
        
        Parameters:
            key (string): 128-bit key for encryption
            message (string): 128-bit message to be encrypted
            
        Returns:
            list: 4x4 matrix array representing the encrypted message after 10 rounds of AES
        """
        # Prepare state and round keys
        matrix_table = self._message_table(message)
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
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, round_keys[r])

        # Final round (no MixColumns)
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, round_keys[10])

        # Convert state to binary string representation of the encrypted message
        ciphertext = ""
        for row in state:
            for byte in row:
                ciphertext += byte
        return ciphertext
    
def main():
    """Main function to test AES encryption with the key and message from message_tuple.py"""
    # Initialize AES cipher
    cipher = AES()
    
    # Print message and key to be used for encryption
    print("=" * 20, "AES Encryption", "=" * 20)
    print("Plaintext message: ")
    print(mt.plaintext)
    print()

    print("Binary representation of plaintext: ")
    print(mt.message)
    print()

    print("Key: ")
    print(mt.key)
    print()

    # Encrypt message using AES encryption and print output
    ciphertext = cipher.encrypt(mt.key, mt.message)
    print("Binary representation of ciphertext:")
    print(ciphertext)
    print()

    print("Hexadecimal representation of ciphertext:")
    print(hex(int(ciphertext, 2))[2:].upper())
    print()
    
if __name__ == "__main__":
    main()



