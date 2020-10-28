from help_func import how_many_blocks_sha, k_ipad, k_opad, how_many_blocks, block_size
from hashlib import sha256


class Hmac:
    __help_encrypt_block = None
    __key_1 = None
    __key_2 = None
    __is_finalized = False

    def _set_key(self, key):
        self.__key = key
        self.__key_1 = k_ipad(key)
        self.__key_2 = k_opad(key)

    def _mac_add_block(self, data_block):
        self.__help_encrypt_block.update(data_block)

    def mac_finalize(self):
        final_result = sha256(self.__key_2 + self.__help_encrypt_block.digest())
        return final_result

    def compute_mac(self, data):
        num_of_get_blocks = 0
        start = 0
        last = block_size
        self.__help_encrypt_block = sha256(self.__key_1)
        num_of_blocks = how_many_blocks_sha(data)
        while num_of_get_blocks != num_of_blocks:
            if num_of_get_blocks == num_of_blocks - 1:
                self.__is_finalized = True

            if self.__is_finalized is False:
                self._mac_add_block(data[start:last])
                start += block_size
                last += block_size
                num_of_get_blocks += 1

            if self.__is_finalized is True:
                self._mac_add_block(data[start:])
                num_of_get_blocks += 1

        self.__is_finalized = False
        return self.mac_finalize()

    def verify_mac(self, data, tag):
        if self.compute_mac(data) == tag:
            return True
        else:
            return False

