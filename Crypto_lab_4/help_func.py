from Crypto.Cipher import AES
from math import ceil

seven = 7
block_size = 16
ipad = 0x36
opad = 0x5c


def int_to_bytes(num):
    return num.to_bytes(16, byteorder='big')


def shift_one_left(array):
    value = int.from_bytes(array, byteorder="big")
    new = value << 1
    return int_to_bytes(new)


def first_bit(array):
    array_bites = []
    array_bites.append((array[0] >> seven) & 1)
    return array_bites[0]


def get_omac_pad(data, block_size):
    padding_size = block_size - len(data[0:])
    if padding_size > 0:
        if padding_size == 1:
            padding = bytes([128])
            return padding
        else:
            padding = bytes([128])
            for i in range(padding_size - 1):
                padding = padding + bytes([0])
            return padding
    else:
        return None


def const_omac():
    r_128 = bytes([0])
    for i in range(6):
        r_128 = r_128 + bytes([0])
    r_128 = r_128 + bytes([135])
    return r_128


def k_ipad(key):
    k_xor_ipad = bytearray()
    for i in range(len(key)):
        k_xor_ipad.append(key[i] ^ ipad)
    return bytes(k_xor_ipad)


def k_opad(key):
    k_xor_opad = bytearray()
    for i in range(len(key)):
        k_xor_opad.append(key[i] ^ opad)
    return bytes(k_xor_opad)


def get_pad_pkcs_5(data, block_size): #ищет паддинг для одного блока, а не для массива
    padding_size = block_size - len(data[0:])
    if padding_size > 0:
        padding = (chr(padding_size) * padding_size)
        return padding.encode() #возвращаю байты
    else:
        return None


def get_hmac_pad(data, block_size):
    return None


def arr_concat_pad(data, padding):
    if padding is None:
        return data
    else:
        return data + padding


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


def how_many_blocks(data):
    num = len(data) / 16
    if type(num) == int:
        return num
    else:
        return ceil(num)


def how_many_blocks_sha(data):
    num = len(data) / 64
    if type(num) == int:
        return num
    else:
        return ceil(num)


def aes_block_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

