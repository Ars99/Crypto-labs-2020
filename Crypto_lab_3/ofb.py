from help_func import how_many_blocks, aes_block_decrypt, aes_block_encrypt, xor_two_arr
import os


def ofb_encrypt(key, data, iv):
    if iv is None:
        iv = os.urandom(16)
    encrypt_arr = bytearray()
    num_of_get_blocks = 0
    start = 0
    last = 16
    is_final_block = False
    num_of_blocks = how_many_blocks(data)
    encrypt_arr.extend(bytearray(iv))
    if num_of_blocks == 1:
        help_arr = aes_block_encrypt(key, iv, is_final_block, None)
        encrypt_arr.extend(bytearray(xor_two_arr(data[start:], help_arr)))
    else:
        help_arr = aes_block_encrypt(key, iv, is_final_block, None)
        encrypt_arr.extend(bytearray(xor_two_arr(data[start:last], help_arr)))
        num_of_get_blocks += 1
        start += 16
        last += 16
        while num_of_get_blocks != num_of_blocks:
            if num_of_get_blocks == num_of_blocks - 1:
                is_final_block = True
            if is_final_block is False:
                help_arr = aes_block_encrypt(key, help_arr, is_final_block, None)
                encrypt_arr.extend(bytearray(xor_two_arr(data[start:last], help_arr)))
                num_of_get_blocks += 1
                start += 16
                last += 16
            if is_final_block is True:
                help_arr = aes_block_encrypt(key, help_arr, is_final_block, None)
                encrypt_arr.extend(bytearray(xor_two_arr(data[start:], help_arr)))
                num_of_get_blocks += 1
    return encrypt_arr


def ofb_decrypt(key, data, iv):
    if iv is None:
        iv = data[0:16]
    data = data[16:]
    decrypt_arr = bytearray()
    num_of_get_blocks = 0
    start = 0
    last = 16
    is_final_block = False
    num_of_blocks = how_many_blocks(data)
    if num_of_blocks == 1:
        help_arr = aes_block_encrypt(key, iv, is_final_block, None)
        decrypt_arr.extend(bytearray(xor_two_arr(data[start:], help_arr)))
    else:
        help_arr = aes_block_encrypt(key, iv, is_final_block, None)
        decrypt_arr.extend(bytearray(xor_two_arr(data[start:last], help_arr)))
        num_of_get_blocks += 1
        start += 16
        last += 16
        while num_of_get_blocks != num_of_blocks:
            if num_of_get_blocks == num_of_blocks - 1:
                is_final_block = True
            if is_final_block is False:
                help_arr = aes_block_encrypt(key, help_arr, is_final_block, None)
                decrypt_arr.extend(bytearray(xor_two_arr(data[start:last], help_arr)))
                num_of_get_blocks += 1
                start += 16
                last += 16
            if is_final_block is True:
                help_arr = aes_block_encrypt(key, help_arr, is_final_block, None)
                decrypt_arr.extend(bytearray(xor_two_arr(data[start:], help_arr)))
                num_of_get_blocks += 1
    return decrypt_arr
