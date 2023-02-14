from ctypes import c_int8


def int8_from_value(value: int) -> int:
    return c_int8(value & 0xFF).value
