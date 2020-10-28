from help_func import how_many_blocks, aes_block_decrypt, aes_block_encrypt, init_vec_ctr, xor_two_arr
from help_func import int_to_bytes_4, bytes_to_int
import os
block_size = 16


def ctr_encrypt(key, data, iv):
    num_of_get_blocks = 0
    if iv is None:
        nonce = os.urandom(4)
        iv = init_vec_ctr(nonce, 0, num_of_get_blocks)
    encrypt_arr = bytearray()
    start = 0
    last = 16
    is_final_block = False
    num_of_blocks = how_many_blocks(data)
    encrypt_arr.extend(bytearray(iv))
    while num_of_get_blocks != num_of_blocks:
        if num_of_get_blocks == num_of_blocks - 1:
            is_final_block = True
        if is_final_block is False:
            encrypt_arr.extend(bytearray(xor_two_arr(data[start:last], aes_block_encrypt(key, iv, is_final_block,
                                                                                         None))))
            num_of_get_blocks += 1
            start += 16
            last += 16
            iv = iv[0:12] + (int_to_bytes_4(bytes_to_int(iv[12:16]) + 1))
        if is_final_block is True:
            encrypt_arr.extend(bytearray(xor_two_arr(data[start:], aes_block_encrypt(key, iv, is_final_block, None))))
            num_of_get_blocks += 1
    return encrypt_arr


def ctr_decrypt(key, data, iv):
    if iv is None:
        iv = data[0:16]
    data = data[16:]
    num_of_get_blocks = 0
    decrypt_arr = bytearray()
    start = 0
    last = 16
    is_final_block = False
    num_of_blocks = how_many_blocks(data)
    while num_of_get_blocks != num_of_blocks:
        if num_of_get_blocks == num_of_blocks - 1:
            is_final_block = True
        if is_final_block is False:
            decrypt_arr.extend(bytearray(xor_two_arr(data[start:last], aes_block_encrypt(key, iv, is_final_block,
                                                                                         None))))
            num_of_get_blocks += 1
            start += 16
            last += 16
            iv = iv[0:12] + (int_to_bytes_4(bytes_to_int(iv[12:16]) + 1))
        if is_final_block is True:
            decrypt_arr.extend(bytearray(xor_two_arr(data[start:], aes_block_encrypt(key, iv, is_final_block,
                                                                                     None))))
            num_of_get_blocks += 1
    return decrypt_arr
