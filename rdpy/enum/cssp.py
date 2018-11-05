from enum import IntEnum


class TSRequestField(IntEnum):
    VERSION = 0
    NEGO_DATA = 1
    AUTH_INFO = 2
    PUB_KEY_AUTH = 3
    ERROR_CODE = 4
    CLIENT_NONCE = 5