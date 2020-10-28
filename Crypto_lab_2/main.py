from hashlib import sha256
import os
import sys
from collections import deque
import threading
import math
import graphics_build
from time import time
import matplotlib.pyplot as plt
import numpy as np

sixteen = 16
fourteen = 14
twenty = 20
eight = 8
seven = 7
two = 2
three = 3
four = 4
five = 5
six = 6
size_of_input_arr = 32
time_birthday = []
memory_birthday = []
table_birthday = {}
num_of_sha = [15, 16, 17, 18, 19, 20]


def int_to_bytes(num):
    return num.to_bytes(8, byteorder='big')


def str_to_bytes(str):
    return bytearray(str,"utf-8")

def first_bites(array, num_of_bits):
    array_bites = []
    if num_of_bits <= sixteen and num_of_bits > fourteen:
        for i in range(eight):
            array_bites.append((array[0] >> i) & 1)

        if num_of_bits == 15:
            for i in range(seven):
                array_bites.append((array[1] >> i) & 1)

        if num_of_bits == 16:
            for i in range(eight):
                array_bites.append((array[1] >> i) & 1)

    if num_of_bits > sixteen and num_of_bits <= twenty:
        for j in range(two):
            for i in range(eight):
                array_bites.append((array[j] >> i) & 1)
        if num_of_bits == 17:
            array_bites.append((array[2] >> 1) & 1)
        if num_of_bits == 18:
            for i in range(1):
                array_bites.append((array[2] >> i) & 1)
        if num_of_bits == 19:
            for i in range(two):
                array_bites.append((array[2] >> i) & 1)
        if num_of_bits == 19:
            for i in range(three):
                array_bites.append((array[2] >> i) & 1)
        if num_of_bits == 20:
            for i in range(four):
                array_bites.append((array[2] >> i) & 1)
    return array_bites


def sha_xx(array, num_of_bites):
    hash_of_array = str_to_bytes(sha256(array).hexdigest())
    array_sha_xx = first_bites(hash_of_array, num_of_bites)
    return array_sha_xx


def birthday(num_sha):
    dictionary = {}
    cont = True
    while cont:
        vector_entry = os.urandom(size_of_input_arr)
        vector_hash = sha_xx(vector_entry, num_sha)
        vector_hash = tuple(vector_hash)
        if vector_hash in dictionary:
            return {'1': vector_entry.hex(), '2': dictionary[vector_hash].hex()}
        else:
            dictionary[vector_hash] = vector_entry


def birthday_memory_is(num_sha):
    dictionary = {}
    cont = True
    i = 0
    while cont:
        vector_entry = os.urandom(size_of_input_arr)
        vector_hash = sha_xx(vector_entry, num_sha)
        vector_hash = tuple(vector_hash)
        if vector_hash in dictionary:
            return i
        else:
            dictionary[vector_hash] = vector_entry
            i += 1


def total_memory(num_sha):
    need = 0
    for i in range(100):
        need_mem = (birthday_memory_is(num_sha)) * (num_sha + size_of_input_arr)
        need = need + need_mem
    return need // 100




