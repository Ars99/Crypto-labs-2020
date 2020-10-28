from help_func import how_many_blocks, aes_block_encrypt, init_vec_ctr, xor_two_arr
from help_func import int_to_bytes_4, bytes_to_int
import hmac


class Authentic:
    def __init__(self, is_encrypt_arr):
        self.__is_encrypt_arr = is_encrypt_arr

    def _set_key(self, key, hmac_key, iv):
        self.__key = key
        self.__iv = iv
        self.__hmac_key = hmac_key
        self.__Hmac_encrypt = hmac.new(hmac_key, msg=None)
        self.__Hmac_decrypt = hmac.new(hmac_key, msg=None)

    def _add_block(self, data_block, iv, is_final_block, get_hmac):
        if self.__is_encrypt_arr is True:
            self.__Hmac_encrypt.update(xor_two_arr(data_block, aes_block_encrypt(self.__key, iv)))
            return xor_two_arr(data_block, aes_block_encrypt(self.__key, iv))

        elif self.__is_encrypt_arr is False:
            if is_final_block is False:
                self.__Hmac_decrypt.update(data_block)
                return xor_two_arr(data_block, aes_block_encrypt(self.__key, iv))
            else:
                self.__Hmac_decrypt.update(data_block)
                if self.__Hmac_decrypt.digest() == get_hmac:
                    return xor_two_arr(data_block, aes_block_encrypt(self.__key, iv))
                else:
                    return None

    def process_data(self, data):
        if self.__is_encrypt_arr:
            is_final_block = False
            num_of_get_blocks = 0
            start = 0
            last = 16
            encrypt_arr = bytearray()
            num_of_blocks = how_many_blocks(data)
            encrypt_arr.extend(self.__iv)
            while num_of_get_blocks != num_of_blocks:
                if num_of_get_blocks == num_of_blocks - 1:
                    is_final_block = True
                if is_final_block is False:
                    encrypt_arr.extend(self._add_block(data[start:last], self.__iv, is_final_block, None))
                    num_of_get_blocks += 1
                    start += 16
                    last += 16
                    self.__iv = self.__iv[0:12] + (int_to_bytes_4(bytes_to_int(self.__iv[12:16]) + 1))
                if is_final_block is True:
                    encrypt_arr.extend(self._add_block(data[start:], self.__iv, is_final_block, None))
                    num_of_get_blocks += 1
            encrypt_arr.extend(self.__Hmac_encrypt.digest())
            return encrypt_arr

        elif self.__is_encrypt_arr is False:
            decrypt_arr = bytearray()
            get_hmac = data[len(data) - 16:]
            iv = data[0:16]
            data = data[16:len(data) - 16]
            num_of_get_blocks = 0
            start = 0
            last = 16
            is_final_block = False
            num_of_blocks = how_many_blocks(data)
            while num_of_get_blocks != num_of_blocks:
                if num_of_get_blocks == num_of_blocks - 1:
                    is_final_block = True
                if is_final_block is False:
                    decrypt_arr.extend(self._add_block(data[start:last], iv, is_final_block, None))
                    num_of_get_blocks += 1
                    start += 16
                    last += 16
                    iv = iv[0:12] + (int_to_bytes_4(bytes_to_int(iv[12:16]) + 1))
                if is_final_block is True:
                    final = self._add_block(data[start:], iv, is_final_block, get_hmac)
                    if final is not None:
                        decrypt_arr.extend(final)
                    else:
                        decrypt_arr = []
                    num_of_get_blocks += 1
            if len(decrypt_arr) != 0:
                return decrypt_arr
            else:
                return []

