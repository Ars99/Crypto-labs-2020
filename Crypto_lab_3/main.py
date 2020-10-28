from Crypto.Cipher import AES
from math import ceil
from encrypt_interface import aes_encrypt
from decrypt_interface import aes_decrypt
import os
# block_size = 16


def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

key = hex_to_bytes('140b41b22a29beb4061bda66b6747e14')
data = hex_to_bytes('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d'
                    '04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')
print(aes_decrypt(key, data, 'cbc', None))

key = hex_to_bytes('140b41b22a29beb4061bda66b6747e14')
data = hex_to_bytes('5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4af'
                    'c48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253')
print(aes_decrypt(key, data, 'cbc', None))


key = hex_to_bytes('36f18357be4dbd77f050515c73fcf9f2')
data = hex_to_bytes('69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb50'
                    '54dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329')
print(aes_decrypt(key, data, 'ctr', None))

key = hex_to_bytes('36f18357be4dbd77f050515c73fcf9f2')
data = hex_to_bytes('770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')
print(aes_decrypt(key, data, 'ctr', None))

key = hex_to_bytes('36f18357be4dbd77f050515c73fcf9f2')
data = hex_to_bytes('746869732074657874206861732074776f20616e642068616c6620626c6f636b732e206e69636521')
print(aes_decrypt(key, bytes(aes_encrypt(key, data, 'ecb', None)), 'ecb', None))
print(aes_decrypt(key, bytes(aes_encrypt(key, data, 'cfb', None)), 'cfb', None))
print(aes_decrypt(key, bytes(aes_encrypt(key, data, 'ofb', None)), 'ofb', None))
print(aes_decrypt(key, bytes(aes_encrypt(key, data, 'cbc', None)), 'cbc', None))
print(aes_decrypt(key, bytes(aes_encrypt(key, data, 'ctr', None)), 'ctr', None))





