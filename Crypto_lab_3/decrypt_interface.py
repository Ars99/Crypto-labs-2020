from ctr import ctr_decrypt
from ofb import ofb_decrypt
from cfb import cfb_decrypt
from cbc import cbc_decrypt
from ecb import ecb_decrypt


def aes_decrypt(key, data, mode, iv):
    if mode == 'ecb':
        return ecb_decrypt(key, data, iv)
    elif mode == 'cbc':
        return cbc_decrypt(key, data, iv)
    elif mode == 'cfb':
        return cfb_decrypt(key, data, iv)
    elif mode == 'ofb':
        return ofb_decrypt(key, data, iv)
    elif mode == 'ctr':
        return ctr_decrypt(key, data, iv)
