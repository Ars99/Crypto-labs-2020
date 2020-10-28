from enc_then_mac import Authentic
import os


def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

def init_vec_ctr(nonce, counter_msg, counter_block):
    return nonce + int_to_bytes_8(counter_msg) + int_to_bytes_4(counter_block)


def int_to_bytes_4(num):
    return num.to_bytes(4, byteorder='big')


def int_to_bytes_8(num):
    return num.to_bytes(8, byteorder='big')

def ok(data, ciph_2):
    if data.hex() == bytes(ciph_2).hex():
        print('ok')
    else:
        print('no')


data = os.urandom(1048576)

key = hex_to_bytes('36f18357be4dbd77f050515c73fcf9f2')
nonce = os.urandom(4)
iv = init_vec_ctr(nonce, 0, 0)
hmac_key = os.urandom(16)

ciph_1 = bytearray()
auth_1 = Authentic(True)
auth_1._set_key(key, hmac_key, iv)
ciph_1.extend(auth_1.process_data(data))



ciph_2 = bytearray()
auth_2 = Authentic(False)
auth_2._set_key(key, hmac_key, iv)
ciph_2.extend(auth_2.process_data((ciph_1)))

print(ok(data, ciph_2))

