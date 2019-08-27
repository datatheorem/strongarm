from enum import Enum


class RegisterContentsType(Enum):
    IMMEDIATE = 0
    UNKNOWN = 1


class RegisterContents:
    def __init__(self, value_type: RegisterContentsType, value: int) -> None:
        self.type = value_type
        self.value = value


