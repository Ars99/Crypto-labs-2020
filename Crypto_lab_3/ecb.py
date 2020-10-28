from help_func import how_many_blocks, get_pad_pkcs_7, aes_block_decrypt, aes_block_encrypt
block_size = 16


def ecb_encrypt(key, data, iv=None):
    decrypt_arr = bytearray()
    num_of_blocks = how_many_blocks(data)
    num_of_get_blocks = 0
    start = 0
    last = 16
    is_final_block = False
    while num_of_get_blocks != num_of_blocks:
        if num_of_get_blocks == num_of_blocks - 1:
            is_final_block = True

        if is_final_block is False:
            padding = None
            decrypt_arr.extend(bytearray(aes_block_decrypt(key, data[start:last], is_final_block, padding)))
            num_of_get_blocks += 1
            start += 16
            last += 16

        if is_final_block is True:
            padding = get_pad_pkcs_7(data[start:], block_size)
            decrypt_arr.extend(bytearray(aes_block_decrypt(key, data[start:], is_final_block, padding)))
            num_of_get_blocks += 1
    return decrypt_arr


def ecb_decrypt(key, data, iv=None):
    encrypt_arr = bytearray()
    num_of_blocks = how_many_blocks(data)
    num_of_get_blocks = 0
    start = 0
    last = 16
    is_final_block = False
    while num_of_get_blocks != num_of_blocks:
        if num_of_get_blocks == num_of_blocks - 1:
            is_final_block = True

        if is_final_block is False:
            padding = None
            encrypt_arr.extend(bytearray(aes_block_encrypt(key, data[start:last], is_final_block, padding)))
            num_of_get_blocks += 1
            start += 16
            last += 16

        if is_final_block is True:
            padding = get_pad_pkcs_7(data[start:], block_size)
            encrypt_arr.extend(bytearray(aes_block_encrypt(key, data[start:], is_final_block, padding)))
            num_of_get_blocks += 1
    return encrypt_arr
