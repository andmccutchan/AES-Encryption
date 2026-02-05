import message_tuple as mt

class AES:
    def __init__(self, key, message):
        self.key = key
        self.message = message
        
    def message_table(self, message):
        table = [[], [], [], []]
        for i in range(0, len(message), 8):
            byte = message[i:i+8]
            row_index = i // 8 % 4
            table[row_index].append(byte)
        return table
    
    def shift_rows(self, table):
        shifted_table = []
        for i in range(4):
            if i == 0:
                shifted_table.append(table[i])
            elif i == 1:
                shifted_table.append(table[i][1:] + table[i][:1])
            elif i == 2:
                shifted_table.append(table[i][2:] + table[i][:2])
            elif i == 3:
                shifted_table.append(table[i][3:] + table[i][:3])
        return shifted_table
        
    def encrypt(key, message):
        # Placeholder for AES encryption logic
        pass
        

    
   
def main():
    cipher = AES(mt.key, mt.message)
    
    cipher_table = cipher.message_table(cipher.message)
    print("Cipher Table:")
    print(cipher_table)
    shifted_table = cipher.shift_rows(cipher_table)
    print("Shifted Table:")
    print(shifted_table)
    
if __name__ == "__main__":
    main()




def mixColumns(state):
    
    for i in range(4):
        s0 = state[0][i]
        s1 = state[1][i]
        s2 = state[2][i]
        s3 = state[3][i]

        s0 = (timesTwo(state[0][i]) ^ timesThree(state[1][i]) ^ state[2][i] ^ state[3][i]) & 0xff
        s1 = (state[0][i] ^ timesTwo(state[1][i]) ^ timesThree(state[2][i]) ^ state[3][i]) & 0xff
        s2 = (state[0][i] ^ state[1][i] ^ timesTwo(state[2][i]) ^ timesThree(state[3][i])) & 0xff
        s3 = (timesThree(state[0][i]) ^ state[1][i] ^ state[2][i] ^ timesTwo(state[3][i])) & 0xff

        state[0][i] = s0
        state[1][i] = s1
        state[2][i] = s2
        state[3][i] = s3

def timesTwo(byte):
    if byte & 0x80:
        return ((byte << 1) ^ 0x1b) & 0xff
    else:
        return (byte << 1) & 0xff

def timesThree(byte):
    return timesTwo(byte) ^ byte
    

def testMixColumns():
    state = [
        [0x87, 0xf2, 0x4d, 0x97],
        [0x6e, 0x4c, 0x90, 0xec],
        [0x46, 0xe7, 0x4a, 0xc3],
        [0xa6, 0x8c, 0xd8, 0x95]
    ]
    mixColumns(state)
    expected = [
        [0x47, 0x40, 0xa3, 0x4c],
        [0x37, 0xd4, 0x70, 0x9f],
        [0x94, 0xe4, 0x3a, 0x42],
        [0xed, 0xa5, 0xa6, 0xbc]
    ]
    assert state == expected, f"Expected {expected}, but got {state}"

testMixColumns()