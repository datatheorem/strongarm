from ctypes import c_int8, c_int32


def int8_from_value(value: int) -> int:
    return c_int8(value & 0xFF).value


def int24_from_value(value: int) -> int:
    return c_int32(value & 0xFFFFFF).value
