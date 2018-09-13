# -*- coding: utf-8 -*-
from enum import Enum


class RegisterContentsType(Enum):
    FUNCTION_ARG = 0
    IMMEDIATE = 1
    UNKNOWN = 2


class RegisterContents:
    def __init__(self, value_type: RegisterContentsType, value: int) -> None:
        self.type = value_type
        self.value = value


