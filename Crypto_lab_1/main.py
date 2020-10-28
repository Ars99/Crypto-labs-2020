import os
import hashlib
from hashlib import sha256
from collections import Counter
import json

blocksize = 64
opad = 0x5c
ipad = 0x36
keys_get = []
iterations = 1001 #hmac
passwords = []
xts = os.urandom(32)
filename = 'datafile.json'
ctx = bytearray(b"Arseny")
num_of_iterations_pbkdf = 10000 #pbkdf
zero = 0
iterator_five = 5
hmac_len = 64
key_len = 64

def int_to_bytes(num):
    return num.to_bytes(8, byteorder='big')


def str_to_bytes(str):
    return str.encode('utf-8')


def str_to_bytes_ascii(str):
    return str.encode('ascii')

def hmacsha256(key, data):
    k_xor_opad = bytearray()
    k_xor_ipad = bytearray()

    if len(key) > blocksize:
        key = sha256(key)

    if len(key) < blocksize:
        key = (zero).to_bytes(blocksize - len(key), byteorder='big')

    for i in range(len(key)):
        k_xor_opad.append(key[i] ^ opad)
        k_xor_ipad.append(key[i] ^ ipad)
    return bytearray(sha256(k_xor_opad + str_to_bytes((sha256(k_xor_ipad + data)).hexdigest())).hexdigest(), encoding='ascii')


def hkdfextract(xts, skm):
    return hmacsha256(xts, skm)


def hkdfexpand(prk, lastkey, ctx, i):
    return hmacsha256(prk, lastkey + ctx + int_to_bytes(i))


def keygenerator(xts, skm, ctx, iterations):
    prk = hkdfextract(xts, skm)
    keys = []
    keys.append(hmacsha256(prk, ctx + bytearray(zero)))
    for i in range(1, iterations):
        keys.append(hkdfexpand(prk, keys[i-1], ctx, i))
    return keys[1:]


def getfirstfivebits(keys_get, key_number):
    s = keys_get[key_number]
    first_eight_bits = s[zero]
    first_five_bits = ''
    for j in range(iterator_five):
        first_five_bits = first_five_bits + str(((first_eight_bits >> j) & 1))
    reverse_five_bits = first_five_bits[::-1]
    return (int(reverse_five_bits, base=2))


def firstfivebitsofallkeys(keys_get):
    list_of_five_bits = []
    for i in range(len(keys_get)):
        list_of_five_bits.append(getfirstfivebits(keys_get, i))
    return list_of_five_bits


def pbkdf_2(password, salt, num_of_iterations, i):
    salt_cat_i = salt + int_to_bytes(i)
    u_prev = hmacsha256(password, salt_cat_i)
    result_of_func = u_prev
    for i in range(num_of_iterations):
        u_prev = hmacsha256(password, u_prev)
        for j in range(len(result_of_func)):
            result_of_func[j] = result_of_func[j] ^ u_prev[j]
    return result_of_func


def keygenerator_pbkdf_2(password, salt, num_of_iterations, key_len):
    t_i = pbkdf_2(password, salt, num_of_iterations, 1)
    key = t_i
    for i in range(key_len // hmac_len):
        key = key + pbkdf_2(password, salt, num_of_iterations, i)
    return key

# with open(filename) as fd:
#     h = hashlib.new('sha256')
#     h.update(str_to_bytes(fd.read()))
# skm = str_to_bytes(h.hexdigest())
# keys_get = keygenerator(xts, skm, ctx, iterations)
# list_of_five_bits = firstfivebitsofallkeys(keys_get)
# list_of_five_bits.sort()
# count_elements_quantity = Counter(list_of_five_bits)

with open("passwords.json", "r") as read_file:
    passwords = json.load(read_file)
passwords_bytes = []
for i in range(1000):
    passwords_bytes.append(str_to_bytes(passwords[i]))
# list_of_five_bits_pass = firstfivebitsofallkeys(passwords_bytes)
# list_of_five_bits_pass.sort()
# count_elements_quantity_pass = Counter(list_of_five_bits_pass)
#
# key_pbkdf_bits = []
# key_pbkdf = []
# for i in range(2):
#     key_pbkdf.append(keygenerator_pbkdf_2(passwords_bytes[i], xts, num_of_iterations_pbkdf, key_len))
# print(type(key_pbkdf[0]))

key_pbkdf_bits = []
key_pbkdf = []
for i in range(1000):
    key_pbkdf.append(keygenerator_pbkdf_2(passwords[i], xts, num_of_iterations_pbkdf, key_len))
key_pbkdf_bits = firstfivebitsofallkeys(key_pbkdf)
key_pbkdf_bits.sort()
count_elements_quantity_pbkdf = Counter(key_pbkdf_bits)
print(count_elements_quantity_pbkdf)
