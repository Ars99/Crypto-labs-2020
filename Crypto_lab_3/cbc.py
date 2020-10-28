from help_func import how_many_blocks, get_pad_pkcs_7, aes_block_decrypt, aes_block_encrypt, arr_pad, xor_two_arr
import os
block_size = 16


def cbc_encrypt(key, data, iv):
    encrypt_arr = bytearray()
    if iv is None:
        iv = os.urandom(16)
    num_of_get_blocks = 0
    start = 0
    last = 16
    is_final_block = False
    num_of_blocks = how_many_blocks(data)
    encrypt_arr.extend(bytearray(iv))
    if num_of_blocks == 1:
        is_final_block = True
        padding = get_pad_pkcs_7(data, block_size)
        data = arr_pad(data, padding)
        data = xor_two_arr(data, iv)
        padding = get_pad_pkcs_7(data, block_size)
        encrypt_arr.extend(bytearray(aes_block_encrypt(key, data, is_final_block, padding)))

    else:
        padding = None
        help_arr = aes_block_encrypt(key, xor_two_arr(data[start:last], iv), is_final_block, padding)
        encrypt_arr.extend(bytearray(help_arr))
        num_of_get_blocks += 1
        start += 16
        last += 16

        while num_of_get_blocks != num_of_blocks:
            if num_of_get_blocks == num_of_blocks - 1:
                is_final_block = True

            if is_final_block is False:
                padding = None
                help_arr = aes_block_encrypt(key, xor_two_arr(help_arr, data[start:last]), is_final_block, padding)
                encrypt_arr.extend(bytearray(help_arr))
                num_of_get_blocks += 1
                start += 16
                last += 16

            if is_final_block is True:
                padding = get_pad_pkcs_7(data[start:], block_size)
                help_arr = aes_block_encrypt(key, xor_two_arr(help_arr, arr_pad(data[start:], padding)), is_final_block,
                                             None)
                encrypt_arr.extend(bytearray(help_arr))
                num_of_get_blocks += 1
    return encrypt_arr


def cbc_decrypt(key, data, iv):
    decrypt_arr = bytearray()
    if iv is None:
        iv = data[0:16]
    data = data[16:]
    start = 0
    last = 16
    is_final_block = False
    num_of_blocks = how_many_blocks(data)
    num_of_get_blocks = 0
    if num_of_blocks == 1:
        is_final_block = True
        padding = get_pad_pkcs_7(data, block_size)
        help_arr = aes_block_decrypt(key, data, is_final_block, padding)
        decrypt_arr.extend(bytearray(xor_two_arr(iv, help_arr)))
    else:
        padding = get_pad_pkcs_7(data[start:last], block_size)
        decrypt_arr.extend(xor_two_arr(iv, aes_block_decrypt(key, data[start:last], is_final_block, padding)))
        start += 16
        last += 16
        num_of_get_blocks += 1
        while num_of_get_blocks != num_of_blocks:
            if num_of_get_blocks == num_of_blocks - 1:
                is_final_block = True
            if is_final_block is False:
                padding = None
                help_arr = data[start - 16:last - 16]
                decrypt_arr.extend(bytearray(xor_two_arr(help_arr, aes_block_decrypt(key, data[start:last], is_final_block,
                                             padding))))
                start += 16
                last += 16
                num_of_get_blocks += 1
            if is_final_block is True:
                help_arr = data[start - 16:last - 16]
                padding = get_pad_pkcs_7(data[start:], block_size)
                decrypt_arr.extend(bytearray(xor_two_arr(help_arr, aes_block_decrypt(key, data[start:], is_final_block,
                                                                                     padding))))
                num_of_get_blocks += 1
    return decrypt_arr
