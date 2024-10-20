# 置换函数，将输入 bits 根据 table 中的索引顺序进行置换
def permute(bits, table):
    if max(table) >= len(bits):
        raise IndexError(f"置换表中的索引超出二进制列表的长度：max(table)={max(table)}, len(bits)={len(bits)}")
    return [bits[i] for i in table]


# 将字符串转化为二进制列表
def str_to_bin_list(s, size):
    if len(s) != size:
        raise ValueError(f"输入的二进制字符串长度应为 {size} 位，但得到 {len(s)} 位")
    if not all(bit in '01' for bit in s):
        raise ValueError("输入的字符串应仅包含二进制位（0 和 1）")
    return [int(bit) for bit in s]


# 将二进制列表转为字符串
def bin_list_to_str(bits):
    return ''.join(map(str, bits))


# 左移函数
def left_shift(bits, n):
    return bits[n:] + bits[:n]


# 密钥扩展函数
def key_schedule(key):
    P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
    P8 = [5, 2, 6, 3, 7, 4, 9, 8]

    key = permute(key, P10)
    left_half, right_half = key[:5], key[5:]

    K1 = permute(left_shift(left_half, 1) + left_shift(right_half, 1), P8)
    K2 = permute(left_shift(left_half, 2) + left_shift(right_half, 2), P8)

    return K1, K2


# S盒代替函数
def sbox(input_bits, sbox_table):
    row = (input_bits[0] << 1) + input_bits[3]
    col = (input_bits[1] << 1) + input_bits[2]
    output = sbox_table[row][col]
    return [(output >> 1) & 1, output & 1]


# f 函数
def f(right, subkey):
    EP = [3, 0, 1, 2, 1, 2, 3, 0]
    P4 = [1, 3, 2, 0]

    S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
    S1 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]

    expanded_right = permute(right, EP)
    xor_result = [expanded_right[i] ^ subkey[i] for i in range(8)]
    return permute(sbox(xor_result[:4], S0) + sbox(xor_result[4:], S1), P4)


# 单轮加密函数 fk
def fk(bits, subkey):
    left, right = bits[:4], bits[4:]
    return [left[i] ^ f(right, subkey)[i] for i in range(4)] + right


# 加密过程
def encrypt(plaintext, key):
    IP = [1, 5, 2, 0, 3, 7, 4, 6]
    IP_inv = [3, 0, 2, 4, 6, 1, 7, 5]

    K1, K2 = key_schedule(key)
    bits = permute(plaintext, IP)
    bits = fk(bits, K1)
    bits = bits[4:] + bits[:4]
    bits = fk(bits, K2)
    return permute(bits, IP_inv)


# 解密过程
def decrypt(ciphertext, key):
    IP = [1, 5, 2, 0, 3, 7, 4, 6]
    IP_inv = [3, 0, 2, 4, 6, 1, 7, 5]

    K1, K2 = key_schedule(key)
    bits = permute(ciphertext, IP)
    bits = fk(bits, K2)
    bits = bits[4:] + bits[:4]
    bits = fk(bits, K1)
    return permute(bits, IP_inv)


# 将字符串转换为ASCII编码的二进制列表
def ascii_to_bin_list(text):
    return [[int(bit) for bit in format(ord(char), '08b')] for char in text]


# 将二进制列表转换回ASCII字符串
def bin_list_to_ascii(bin_list):
    return ''.join(chr(int(''.join(map(str, bin_char)), 2)) for bin_char in bin_list)


# 修改后的加密算法，处理ASCII字符串
def encrypt_ascii(text, key):
    return bin_list_to_ascii([encrypt(bits, key) for bits in ascii_to_bin_list(text)])


# 修改后的解密算法，处理ASCII字符串
def decrypt_ascii(text, key):
    return bin_list_to_ascii([decrypt(bits, key) for bits in ascii_to_bin_list(text)])
