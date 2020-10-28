from help_func import how_many_blocks, aes_block_encrypt, xor_two_arr, get_pad_pkcs_5, block_size, \
     arr_concat_pad

class Trunc_mac:
    __help_encrypt_block = None
    __previous_block = None

    def _set_key(self, key):
        self.__key = key

    def _mac_add_block(self, data_block):
        self.__help_encrypt_block = aes_block_encrypt(self.__key, xor_two_arr(self.__help_encrypt_block,
                                                                                  data_block))
    def mac_finalize(self):
        return self.__help_encrypt_block[8:block_size]

    def compute_mac(self, data):
        num_of_get_blocks = 0
        start = 0
        last = block_size
        num_of_blocks = how_many_blocks(data)
        while num_of_get_blocks != num_of_blocks:
            if num_of_get_blocks == num_of_blocks - 1:
                self.__is_finalized = True
            if num_of_get_blocks != num_of_blocks - 1:
                self._mac_add_block(data[start:last])
                start += block_size
                last += block_size
                num_of_get_blocks += 1
            else:
                padding = get_pad_pkcs_5(data[start:], block_size)
                final_block = arr_concat_pad(data[start:], padding)
                self._mac_add_block(final_block)
                num_of_get_blocks += 1
        return self.mac_finalize()

    def verify_mac(self, data, tag):
        if self.compute_mac(data) == tag:
            return True
        else:
            return False


