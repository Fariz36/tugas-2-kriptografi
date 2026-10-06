BLOCK_SIZE = 16
WORD_SIZE = 4
WORD_MASK = 0xFFFFFFFF
ROUNDS = 16
ROUND_KEY_COUNT = ROUNDS + 1

MAGIC = b"JAV1"
FORMAT_VERSION = 1
TAG_SIZE = 32

MODE_IDS = {
    "ECB": 0,
    "CBC": 1,
    "CFB": 2,
    "OFB": 3,
    "CTR": 4,
}
ID_MODES = {value: key for key, value in MODE_IDS.items()}

MAC_DOMAIN = b"JAV-128/MAC/v1"
