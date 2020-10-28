from math import ceil
from help_func import how_many_blocks, aes_block_encrypt, xor_two_arr, get_omac_pad, block_size, first_bit,\
    shift_one_left, const_omac, arr_concat_pad


class Omac:
    __help_encrypt_block = None
    __previous_block = None
    __num_of_get_blocks = 0

    def _set_key(self, key):
        self.__key = key

    def _mac_add_block(self, data_block):
        if self.__num_of_get_blocks == 0:
            self.__previous_block = data_block
            self.__num_of_get_blocks += 1

        elif self.__num_of_get_blocks == 1:
            self.__help_encrypt_block = aes_block_encrypt(self.__key, self.__previous_block)
            self.__previous_block = data_block
            self.__num_of_get_blocks += 1

        else:
            self.__help_encrypt_block = aes_block_encrypt(self.__key,
                                                          xor_two_arr(self.__previous_block, self.__help_encrypt_block))
            self.__previous_block = data_block
            self.__num_of_get_blocks += 1

    def _mac_finalize(self):
        padding = get_omac_pad(self.__previous_block, block_size)
        null_vector = bytes([0]) * 16
        l = aes_block_encrypt(self.__key, null_vector)
        if first_bit(l) == 0: #нужно ли в bytearray?
            k_1 = shift_one_left(l)
        else:
            k_1 = xor_two_arr(shift_one_left(l), const_omac())

        if padding is None:
            final = aes_block_encrypt(self.__key, xor_two_arr(xor_two_arr(self.__help_encrypt_block,
                                                                          self.__previous_block), k_1))
            self.__num_of_get_blocks = 0
            return final

        elif padding is not None:
            if first_bit(k_1) == 0:
                k_2 = shift_one_left(k_1)
            else:
                k_2 = xor_two_arr(shift_one_left(k_1), const_omac())
            self.__previous_block = arr_concat_pad(self.__previous_block, padding)
            final = aes_block_encrypt(self.__key, xor_two_arr(xor_two_arr(self.__help_encrypt_block,
                                                                          self.__previous_block), k_2))
            self.__num_of_get_blocks = 0
            return final

    def compute_mac(self, data):
        start = 0
        last = block_size
        num_of_blocks = how_many_blocks(data)

        while self.__num_of_get_blocks != num_of_blocks - 1:
            self._mac_add_block(data[start:last])
            start += block_size
            last += block_size

        self._mac_add_block(data[start:])
        result = self._mac_finalize()
        return result

    def verify_mac(self, data, tag):
        if self.compute_mac(data) == tag:
            return True
        else:
            return False

