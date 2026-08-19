import ctypes
import sys

# Константы
# Значения классов объектов согласно спецификации PKCS#11
CKA_CLASS = 0x00000000  # Тип объекта
CKO_DATA = 0x00000000
CKO_CERTIFICATE = 0x00000001
CKO_PUBLIC_KEY = 0x00000002
CKO_PRIVATE_KEY = 0x00000003
CKO_SECRET_KEY = 0x00000004
CKO_HW_FEATURE = 0x00000005
CKO_DOMAIN_PARAMETERS = 0x00000006

# Наиболее часто используемые атрибуты
CKA_LABEL = 0x00000003
CKA_VALUE = 0x00000011
CKA_ID = 0x00000102
CKA_KEY_TYPE = 0x00000100

CKK_RSA = 0x00000000
CKK_EC = 0x00000003
CKK_EC_EDWARDS = 0x00000040
CKK_EC_MONTGOMERY = 0x00000041
CKK_GOSTR3410 = 0x00000030
CKK_VENDOR_DEFINED = 0x80000000
CKK_VENDOR_BIP32 = CKK_VENDOR_DEFINED + 2

# Флаги токена из расширенной информации, используем только необходимые значения
TOKEN_FLAGS_USER_PIN_NOT_DEFAULT = 0x00000008
TOKEN_FLAGS_SUPPORT_JOURNAL = 0x00000400
TOKEN_FLAGS_USER_PIN_UTF8 = 0x00000800
TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE = 0x40000000
TOKEN_FLAGS_FW_CHECKSUM_INVALID = 0x80000000

# Дополнительные атрибуты и механизмы
CKA_TOKEN = 0x00000001
CKA_PRIVATE = 0x00000002
CKA_MODULUS = 0x00000120
CKA_MODULUS_BITS = 0x00000121
CKA_PUBLIC_EXPONENT = 0x00000122
CKA_EC_PARAMS = 0x00000180
CKA_EC_POINT = 0x00000181
CKA_GOSTR3410_PARAMS = 0x00000250
CKA_GOSTR3411_PARAMS = 0x00000251
CKA_DERIVE = 0x0000010C

CKA_VENDOR_DEFINED = 0x80000000
BIP32 = CKA_VENDOR_DEFINED | 0x5000
CKA_VENDOR_BIP32_CHAINCODE = BIP32 | 0x00
CKA_VENDOR_BIP32_ID = BIP32 | 0x01
CKA_VENDOR_BIP32_FINGERPRINT = BIP32 | 0x02
CKA_VENDOR_BIP39_MNEMONIC_TRACE = BIP32 | 0x03
CKA_VENDOR_BIP39_MNEMONIC = BIP32 | 0x04
CKA_VENDOR_BIP39_MNEMONIC_IS_EXTRACTABLE = BIP32 | 0x05

CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000
CKM_RSA_PKCS = 0x00000001
CKM_EC_KEY_PAIR_GEN = 0x00001040
CKM_ECDSA = 0x00001041
CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x00001055
CKM_GOSTR3410_KEY_PAIR_GEN = 0x00001200
CKM_GOSTR3410 = 0x00001201
CKM_VENDOR_DEFINED = 0x80000000
CKM_VENDOR_BIP32_WITH_BIP39_KEY_PAIR_GEN = CKM_VENDOR_DEFINED + 9

CKM_SHA256 = 0x00000250
CKM_GOSTR3411_12_256 = 0x00001225

CKF_SERIAL_SESSION = 1 << 1  # 0x00000002
CKF_RW_SESSION = 1 << 2  # 0x00000004

# Типы пользователей
CKU_USER = 1

# Статусы возврата PKCS#11
CKR_OK = 0x00000000
CKR_TOKEN_NOT_PRESENT = 0x000000E0
CKR_OBJECT_HANDLE_INVALID = 0x00000082

# Структуры PKCS#11

CK_VOID_PTR = ctypes.c_void_p

class CK_VERSION(ctypes.Structure):
    if sys.platform.startswith("win"):
        _pack_ = 1
        _layout_ = "ms"
    _fields_ = [('major', ctypes.c_ubyte), ('minor', ctypes.c_ubyte)]

class CK_INFO(ctypes.Structure):
    if sys.platform.startswith("win"):
        _pack_ = 1
        _layout_ = "ms"
    _fields_ = [
        ('cryptokiVersion', CK_VERSION),
        ('manufacturerID', ctypes.c_char * 32),
        ('flags', ctypes.c_ulong),
        ('libraryDescription', ctypes.c_char * 32),
        ('libraryVersion', CK_VERSION),
    ]

class CK_SLOT_INFO(ctypes.Structure):
    if sys.platform.startswith("win"):
        _pack_ = 1
        _layout_ = "ms"
    _fields_ = [
        ('slotDescription', ctypes.c_char * 64),
        ('manufacturerID', ctypes.c_char * 32),
        ('flags', ctypes.c_ulong),
        ('hardwareVersion', CK_VERSION),
        ('firmwareVersion', CK_VERSION),
    ]

class CK_TOKEN_INFO(ctypes.Structure):
    if sys.platform.startswith("win"):
        _pack_ = 1
        _layout_ = "ms"
    _fields_ = [
        ('label', ctypes.c_char * 32),
        ('manufacturerID', ctypes.c_char * 32),
        ('model', ctypes.c_char * 16),
        ('serialNumber', ctypes.c_char * 16),
        ('flags', ctypes.c_ulong),
        ('ulMaxSessionCount', ctypes.c_ulong),
        ('ulSessionCount', ctypes.c_ulong),
        ('ulMaxRwSessionCount', ctypes.c_ulong),
        ('ulRwSessionCount', ctypes.c_ulong),
        ('ulMaxPinLen', ctypes.c_ulong),
        ('ulMinPinLen', ctypes.c_ulong),
        ('ulTotalPublicMemory', ctypes.c_ulong),
        ('ulFreePublicMemory', ctypes.c_ulong),
        ('ulTotalPrivateMemory', ctypes.c_ulong),
        ('ulFreePrivateMemory', ctypes.c_ulong),
        ('hardwareVersion', CK_VERSION),
        ('firmwareVersion', CK_VERSION),
        ('utcTime', ctypes.c_char * 16),
    ]


class CK_TOKEN_INFO_EXTENDED(ctypes.Structure):
    if sys.platform.startswith("win"):
        _pack_ = 1
        _layout_ = "ms"
    _fields_ = [
        ('ulSizeofThisStructure', ctypes.c_ulong),
        ('ulTokenType', ctypes.c_ulong),
        ('ulProtocolNumber', ctypes.c_ulong),
        ('ulMicrocodeNumber', ctypes.c_ulong),
        ('ulOrderNumber', ctypes.c_ulong),
        ('flags', ctypes.c_ulong),
        ('ulMaxAdminPinLen', ctypes.c_ulong),
        ('ulMinAdminPinLen', ctypes.c_ulong),
        ('ulMaxUserPinLen', ctypes.c_ulong),
        ('ulMinUserPinLen', ctypes.c_ulong),
        ('ulMaxAdminRetryCount', ctypes.c_ulong),
        ('ulAdminRetryCountLeft', ctypes.c_ulong),
        ('ulMaxUserRetryCount', ctypes.c_ulong),
        ('ulUserRetryCountLeft', ctypes.c_ulong),
        ('serialNumber', ctypes.c_ubyte * 8),
        ('ulTotalMemory', ctypes.c_ulong),
        ('ulFreeMemory', ctypes.c_ulong),
        ('ATR', ctypes.c_ubyte * 64),
        ('ulATRLen', ctypes.c_ulong),
        ('ulTokenClass', ctypes.c_ulong),
        ('ulBatteryVoltage', ctypes.c_ulong),
        ('ulBodyColor', ctypes.c_ulong),
        ('ulFirmwareChecksum', ctypes.c_ulong),
        ('ulBatteryPercentage', ctypes.c_ulong),
        ('ulBatteryFlags', ctypes.c_ulong),
    ]

class CK_ATTRIBUTE(ctypes.Structure):
    _pack_ = 1
    _layout_ = "ms"
    _fields_ = [
        ('type', ctypes.c_ulong),
        ('pValue', ctypes.c_void_p),
        ('ulValueLen', ctypes.c_ulong),
    ]


class CK_MECHANISM(ctypes.Structure):
    _pack_ = 1
    _layout_ = "ms"
    _fields_ = [
        ('mechanism', ctypes.c_ulong),
        ('pParameter', ctypes.c_void_p),
        ('ulParameterLen', ctypes.c_ulong),
    ]


class CK_VENDOR_BIP32_WITH_BIP39_KEY_PAIR_GEN_PARAMS(ctypes.Structure):
    _pack_ = 1
    _layout_ = "ms"
    _fields_ = [
        ('pPassphrase', ctypes.c_void_p),
        ('ulPassphraseLen', ctypes.c_ulong),
        ('ulMnemonicLength', ctypes.c_ulong),
    ]
