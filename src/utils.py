import colorsys


def bytes_to_bits_binary(byte_data):
    bits_data = bin(int.from_bytes(byte_data, byteorder='big'))[2:]
    return bits_data

def bits_binary_to_bytes(bits_data):
    byte_data = int(bits_data, 2).to_bytes((len(bits_data) + 7) // 8, byteorder='big')
    return byte_data

def int_to_bits_binary(int_data: int):
    # make len of bits_data equal to 8
    # if len of bits_data is less than 8
    # put 0 to the beginning of bits_data
    bits_data = bin(int_data)[2:]
    bits_data = '0' * (8 - len(bits_data) % 9) + bits_data
    return bits_data

def bits_binary_to_int(bits_data: str):
    return int(bits_data, 2)


def get_hsv(pixel):
    r, g, b = pixel
    h, s, v = colorsys.rgb_to_hsv(r, g, b)
    return h, s, v


def change_v_bits(v, data_to_add):
    v = v[:-1] + data_to_add[0]
    data_to_add = data_to_add[1:]
    return v, data_to_add



