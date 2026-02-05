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




