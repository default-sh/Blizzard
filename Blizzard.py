import binascii


class FileSizeError(Exception):
    """Raised when byte length exceeds 16777215 bytes (0xFFFFFF)"""

    def __init__(self, length):
        self.length = length
        self.message = f"Byte length cannot exceed 16777215 bytes. Your byte length was {length} bytes."
        super().__init__(self.message)


class Hasher:
    """
    Author : Shane H.
    Date of last change : 5/27/2021
    Description :

    This is a project for myself to write a weird hashing algorithm that takes inspiration from MD5 and AES-256.
    The hash will be 16 bytes in the end and goes through three rounds of hashing. This is not designed to be fast,
    nor efficient. It's just an experiment for myself to understand on a low-ish level on how hashing works.
    This probably could have been accomplished without using a class, but for my own purpose of learning, I used a
    class to achieve the usage I wanted. The methods are derived from hashlib.

    TO-DO : Possibly implement some form of threading to make this a passable method of hashing small amounts of data.
    """

    def __init__(self):
        """Initializes four memory spaces for the hashing function to manipulate, and initializes a block size
        variable. This probably wasn't necessary."""
        self.__a: bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        self.__b: bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        self.__c: bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        self.__d: bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        self.__BLOCK_SIZE: int = 16

    def __set_initializers(self):
        """Sets the initializers that the algorithm uses by default. They have no meaning. Mostly."""
        self.__a = b"\x5f\x2c\xaa\x07\x46\x7e\x13\x42"
        self.__b = b"\x2b\xba\x3e\xee\xe4\xa0\x28\x77"
        self.__c = b"\x80\x1f\xf2\x7d\x36\xd0\x70\x76"
        self.__d = b"\x30\xd6\xad\x88\x3c\x91\xd0\x05"

    def __pad(self, file_bytes):
        # Formats the length of the file to be represented in hexadecimal,
        # which can be fed into the bytes.fromhex(<string>) function to generate bytecode.
        size_hex: str = hex(len(file_bytes))[2:]
        if len(size_hex) % 2 != 0:
            size_hex = "0" + hex(len(file_bytes))[2:]

        # Formats the file size to be a 3 byte hex representation.
        while len(size_hex) < 6:
            size_hex = "0" + size_hex

        # Error is thrown if there are more than 6 hex characters, meaning
        # that the file was bigger than this algorithm could handle.
        if len(size_hex) > 6:
            raise FileSizeError(len(file_bytes))

        # 0x80 is 10000000 in binary. Stole this from the MD5 algorithm!
        file_bytes += b"\x80" + bytes.fromhex(size_hex)

        # Appends 0x00 behind the size pad, and in front of the 0x80 padding until LENGTH mod BLOCK_SIZE is true.
        while len(file_bytes) % self.__BLOCK_SIZE != 0:
            file_bytes: bytes = file_bytes[:-3] + b"\x00" + file_bytes[-3:]

        return file_bytes

    def digest(self):
        """Returns the bytecode digest from the hash algorithm."""
        return self.__a[:4] + self.__b[:4] + self.__c[4:] + self.__d[4:]

    def hex_digest(self):
        """Returns the hex representation of the digest from the hash algorithm."""
        return binascii.hexlify(self.__a[:4] + self.__b[:4] + self.__c[4:] + self.__d[4:])

    @staticmethod
    def __rotr(byte, n):
        """Uses some bit magic to rotate a bit to the right by N rotations. Code is based off of the formula presented
        by Smitha Dinesh Semwal in a bit rotation example. """

        while n > 8:
            n -= 8    # This part of the code is just meant to make sure that the rotations are within the confine
        while n < 0:  # of 0 - 8, since the binary width of this operation is 8.
            n += 8

        return int(byte >> n | byte << (8 - n)) & 0xFF

    @staticmethod
    def __rotl(byte, n):
        """Same thing as the right rotation function, but to the left instead."""
        while n > 8:
            n -= 8
        while n < 0:
            n += 8

        return int(byte << n | byte >> (8 - n)) & 0xFF

    def __f1(self, byte1, byte2, byte3, byte4):
        """One of three functions that does some really complicated bit-magic."""
        return (byte2 | self.__rotl(byte4, 3)) ^ ~(self.__rotr(byte1, 1) & byte3) & 0xFF

    def __f2(self, byte1, byte2, byte3, byte4):
        return self.__rotr(byte1, 2) ^ ((byte1 ^ byte4) & ((byte2 ^ byte3) << 2 & 0xFF))

    def __f3(self, byte1, byte2, byte3, byte4):
        return byte4 ^ (self.__rotr((~byte1 | byte3), 5) & 0xFF ^ byte2)

    def __wf1(self, vector: bytes):
        """One of three functions that modify the 8 byte word vectors in a somewhat linear fashion."""
        v_temp: bytes = b""
        v_temp += bytes([self.__rotr(vector[0] ^ vector[7], 1)])
        v_temp += bytes([vector[0] ^ vector[1]])
        v_temp += bytes([self.__rotl(vector[1] ^ vector[2], 2)])
        v_temp += bytes([vector[2] ^ vector[3]])
        v_temp += bytes([self.__rotr(vector[3] ^ vector[4], 1)])
        v_temp += bytes([vector[4] ^ vector[5]])
        v_temp += bytes([self.__rotl(vector[5] ^ vector[6], 2)])
        v_temp += bytes([vector[6] ^ vector[7]])
        return v_temp

    def __wf2(self, vector: bytes):
        v_temp: bytes = b""
        v_temp += bytes([self.__rotr(vector[0] ^ vector[2], 4)])
        v_temp += bytes([self.__rotl(vector[5] ^ vector[7], 1)])
        v_temp += bytes([self.__rotr(vector[1] ^ vector[4], 3)])
        v_temp += bytes([self.__rotl(vector[3] ^ vector[6], 2)])
        v_temp += bytes([self.__rotr(vector[0] ^ vector[3], 2)])
        v_temp += bytes([self.__rotl(vector[7] ^ vector[4], 3)])
        v_temp += bytes([self.__rotr(vector[1] ^ vector[5], 1)])
        v_temp += bytes([self.__rotl(vector[2] ^ vector[6], 4)])
        return v_temp

    @staticmethod
    def __wf3(vector: bytes):
        v_temp: bytes = b""
        v_temp += bytes([vector[0] ^ vector[7]])
        v_temp += bytes([vector[1] ^ vector[6]])
        v_temp += bytes([vector[2] ^ vector[5]])
        v_temp += bytes([vector[3] ^ vector[4]])
        v_temp += bytes([vector[7] ^ vector[4]])
        v_temp += bytes([vector[0] ^ vector[3]])
        v_temp += bytes([vector[1] ^ vector[5]])
        v_temp += bytes([vector[6] ^ vector[2]])
        return v_temp

    def calculate_hash(self, byte_input: bytes):
        self.__set_initializers()
        byte_input: bytes = self.__pad(byte_input)
        byte_input: list[bytes] = [byte_input[i:i + 8] for i in range(0, len(byte_input), 8)]
        for _ in range(3):
            for byte_block in byte_input:
                temp_a: bytes = b""
                for b1, b2, b3, b4 in zip(byte_block, self.__a, self.__b, self.__c):
                    temp_a += bytes([self.__f1(b1, b2, b3, b4)])
                self.__a = self.__wf2(self.__wf1(temp_a))

                temp_b: bytes = b""
                for b1, b2, b3, b4 in zip(byte_block, self.__a, self.__c, self.__d):
                    temp_b += bytes([self.__f2(b1, b2, b3, b4)])
                self.__b = self.__wf3(self.__wf2(temp_b))

                temp_c: bytes = b""
                for b1, b2, b3, b4 in zip(byte_block, self.__a, self.__b, self.__d):
                    temp_c += bytes([self.__f3(b1, b2, b3, b4)])
                self.__c = self.__wf1(self.__wf3(temp_c))

                temp_d: bytes = b""
                for b1, b2, b3, b4 in zip(self.__a, self.__b, self.__c, self.__d):
                    temp_d += bytes([self.__f2(b1, b2, b3, b4)])
                self.__d = self.__wf1(self.__wf1(temp_d))
