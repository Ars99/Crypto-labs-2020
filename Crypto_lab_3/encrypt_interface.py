from ctr import ctr_encrypt
from ofb import ofb_encrypt
from cfb import cfb_encrypt
from cbc import cbc_encrypt
from ecb import ecb_encrypt


def aes_encrypt(key, data, mode, iv):
    if mode == 'ecb':
        return ecb_encrypt(key, data, iv)
    elif mode == 'cbc':
        return cbc_encrypt(key, data, iv)
    elif mode == 'cfb':
        return cfb_encrypt(key, data, iv)
    elif mode == 'ofb':
        return ofb_encrypt(key, data, iv)
    elif mode == 'ctr':
        return ctr_encrypt(key, data, iv)
