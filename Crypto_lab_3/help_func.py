from math import ceil
from Crypto.Cipher import AES


def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)


def str_to_bytes(str):
    return str.encode('utf-8')


def bytes_to_int(byte):
    return int.from_bytes(byte, byteorder='big')


def int_to_bytes_4(num):
    return num.to_bytes(4, byteorder='big')


def int_to_bytes_8(num):
    return num.to_bytes(8, byteorder='big')


def how_many_blocks(data):
    num = len(data) / 16
    if type(num) == int:
        return num
    else:
        return ceil(num)


def xor_two_arr(arr1, arr2):
    if len(arr1) == len(arr2):
        help_arr = bytearray()
        for i in range(len(arr1)):
            help_arr.append(arr1[i] ^ arr2[i])
        return bytes(help_arr)
    elif len(arr1) > len(arr2):
        help_arr = bytearray()
        for i in range(len(arr2)):
            help_arr.append(arr1[i] ^ arr2[i])
        return bytes(help_arr)
    elif len(arr1) < len(arr2):
        help_arr = bytearray()
        for i in range(len(arr1)):
            help_arr.append(arr1[i] ^ arr2[i])
        return bytes(help_arr)


def get_pad_pkcs_7(data, block_size): #ищет паддинг для одного блока, а не для массива
    padding_size = block_size - len(data[0:])
    if padding_size > 0:
        padding = (chr(padding_size) * padding_size)
        return padding #возвращаю строку, потом нужно декодировать в байты
    else:
        return None


def arr_pad(data, padding):
    if padding is None:
        return data
    else:
        return data + padding.encode()


def init_vec_ctr(nonce, counter_msg, counter_block):
    return nonce + int_to_bytes_8(counter_msg) + int_to_bytes_4(counter_block)


def aes_block_encrypt(key, data, is_final_block, padding):
    if is_final_block is False:
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(data)

    elif is_final_block is True:
        data = arr_pad(data, padding)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(data)


def aes_block_decrypt(key, data, is_final_block, padding):
    if is_final_block is False:
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(data)

    elif is_final_block is True:
        data = arr_pad(data, padding)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(data)
