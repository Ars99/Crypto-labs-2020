from bitstring import Bits, BitArray
from omac import Omac
from hmac import Hmac
from truncated_mac import Trunc_mac
from time import time
from random import randint
import os


def average_time(array):
    new = []
    for i in range(len(array)):
        new.append(array[i] / 1000)
    return new

# message_1 = bytes([randint(0, 100)])
# message_2 = bytes([randint(0, 100)])
# message_3 = bytes([randint(0, 100)])
# message_4 = bytes([randint(0, 100)])
#
# time_1 = []
# time_2 = []
#
#
def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

#
# for i in range(102):
#     message_1 = message_1 + bytes([randint(0, 100)])
# for i in range(1024):
#     message_2 = message_2 + bytes([randint(0, 100)])
# for i in range(1024 * 10):
#     message_3 = message_3 + bytes([randint(0, 100)])
# for i in range(1024 * 1000):
#     message_4 = message_4 + bytes([randint(0, 100)])
#
#
# key = os.urandom(16)
#
# tic = time()
# for i in range(1000):
#     first_omac = Omac()
#     first_omac._set_key(key)
#     first_omac.compute_mac(message_1)
# toc = time()
# time_1.append(toc - tic)
#
# tic = time()
# for i in range(1000):
#     first_omac = Omac()
#     first_omac._set_key(key)
#     first_omac.compute_mac(message_2)
# toc = time()
# time_1.append(toc - tic)
#
# tic = time()
# for i in range(1000):
#     first_omac = Omac()
#     first_omac._set_key(key)
#     first_omac.compute_mac(message_3)
# toc = time()
# time_1.append(toc - tic)
#
# tic = time()
# for i in range(1000):
#     first_omac = Omac()
#     first_omac._set_key(key)
#     first_omac.compute_mac(message_4)
# toc = time()
# time_1.append(toc - tic)
#
# print(time_1)
#
#
# tic = time()
# for i in range(1000):
#     first_hmac = Hmac()
#     first_hmac._set_key(key)
#     first_hmac.compute_mac(message_1)
# toc = time()
# time_2.append(toc - tic)
#
# tic = time()
# for i in range(1000):
#     first_hmac = Hmac()
#     first_hmac._set_key(key)
#     first_hmac.compute_mac(message_2)
# toc = time()
# time_2.append(toc - tic)
#
# tic = time()
# for i in range(1000):
#     first_hmac = Hmac()
#     first_hmac._set_key(key)
#     first_hmac.compute_mac(message_3)
# toc = time()
# time_2.append(toc - tic)
#
# tic = time()
# for i in range(1000):
#     first_hmac = Hmac()
#     first_hmac._set_key(key)
#     first_hmac.compute_mac(message_4)
# toc = time()
# time_2.append(toc - tic)
# print(time_2)
#
#
# time_1_average = average_time(time_1)
# time_2_average = average_time(time_2)

# print(time_1_average)
# print(time_2_average)

# a = [0.2088944911956787, 1.6435282230377197, 15.879822015762329, 1582.1726560592651]
# b = [0.02451324462890625, 0.04089069366455078, 0.29421329498291016, 30.492753744125366]
# print(average_time(a))
# print(average_time(b))

key = os.urandom(16)
data = hex_to_bytes('71776572747975696f706173646667686a6b6c7a786376626e6d2c2e2f617173776572646663787a')
first_hmac = Hmac()
first_hmac._set_key(key)
print(len(first_hmac.compute_mac(data).digest()))
print(first_hmac.compute_mac(data).digest())








