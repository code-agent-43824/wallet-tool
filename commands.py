import contextlib
import ctypes
import hashlib
import hmac
import sys
import unicodedata
from pkcs11 import pkcs11_command
from pkcs11_structs import (
    CK_INFO,
    CK_TOKEN_INFO,
    CK_TOKEN_INFO_EXTENDED,
    CK_ATTRIBUTE,
    CKA_CLASS,
    CKA_LABEL,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_VALUE,
    CKO_PUBLIC_KEY,
    CKO_PRIVATE_KEY,
    CKF_SERIAL_SESSION,
    CKF_RW_SESSION,
    CKR_TOKEN_NOT_PRESENT,
    CKR_OK,
    CKR_OBJECT_HANDLE_INVALID,
    CKK_RSA,
    CKK_EC,
    CKK_EC_EDWARDS,
    CKK_EC_MONTGOMERY,
    CKK_GOSTR3410,
    CKK_VENDOR_BIP32,
    CKA_TOKEN,
    CKA_PRIVATE,
    CKA_DERIVE,
    CKA_MODULUS,
    CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_GOSTR3410_PARAMS,
    CKA_GOSTR3411_PARAMS,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKM_GOSTR3410_KEY_PAIR_GEN,
    CKM_GOSTR3410,
    CKM_VENDOR_BIP32_WITH_BIP39_KEY_PAIR_GEN,
    CKM_RSA_PKCS,
    CKM_SHA256,
    CKM_GOSTR3411_12_256,
    CK_MECHANISM,
    CKU_USER,
    CK_VENDOR_BIP32_WITH_BIP39_KEY_PAIR_GEN_PARAMS,
    TOKEN_FLAGS_USER_PIN_NOT_DEFAULT,
    TOKEN_FLAGS_SUPPORT_JOURNAL,
    TOKEN_FLAGS_USER_PIN_UTF8,
    TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE,
    TOKEN_FLAGS_FW_CHECKSUM_INVALID,
    CKA_VENDOR_BIP39_MNEMONIC,
    CKA_VENDOR_BIP39_MNEMONIC_IS_EXTRACTABLE,
    CKA_VENDOR_BIP32_CHAINCODE,
)
from pkcs11_definitions import define_pkcs11_functions

key_type_description = {
    CKK_RSA: "RSA",
    CKK_EC: "ECDSA (bitcoin, ethereum, tron и т.д.)",
    CKK_EC_EDWARDS: "EdDSA (solana, ton и т.д.)",
    CKK_EC_MONTGOMERY: "EdDSA (solana, ton и т.д.)",
    CKK_GOSTR3410: "ГОСТ 34.10-2012",
    CKK_VENDOR_BIP32: "ECDSA (bitcoin, ethereum, tron и т.д.)",
}

SIGN_KEY_CONFIG = {
    CKK_EC: {
        "digest_mechanism": CKM_SHA256,
        "hash_length": 32,
        "sign_mechanism": CKM_ECDSA,
    },
    CKK_VENDOR_BIP32: {
        "digest_mechanism": CKM_SHA256,
        "hash_length": 32,
        "sign_mechanism": CKM_ECDSA,
    },
    CKK_RSA: {
        "digest_mechanism": CKM_SHA256,
        "hash_length": 32,
        "sign_mechanism": CKM_RSA_PKCS,
        "rsa_digest_info_prefix": bytes.fromhex(
            "3031300d060960864801650304020105000420"
        ),
    },
    CKK_GOSTR3410: {
        "digest_mechanism": CKM_GOSTR3411_12_256,
        "hash_length": 32,
        "sign_mechanism": CKM_GOSTR3410,
    },
}

# OID кривой secp256k1 (1.3.132.0.10) в DER, для CKA_EC_PARAMS.
# Именно её использует BIP32: мастер-ключ выводится через HMAC-SHA512 с ключом
# "Bitcoin seed", а это определение из спецификации биткойна. Референс вендора
# (KeyFromSeed.c, GenerateKeyAndGetSeed.c) тоже берёт secp256k1 по умолчанию.
SECP256K1_OID_DER = bytes(
    (
        0x06,
        0x05,
        0x2B,
        0x81,
        0x04,
        0x00,
        0x0A,
    )
)


def format_attribute_value(value: bytes, mode: str) -> str:
    """Return string representation of attribute value.

    Parameters
    ----------
    value: bytes
        Raw value returned from PKCS#11.
    mode: str
        Either ``"hex"`` or ``"text"``.

    Returns
    -------
    str
        String suitable for console output. If value cannot be represented in
        requested mode, ``"двоичные данные"`` is returned.
    """

    if mode == "hex":
        hex_part = " ".join(f"{b:02X}" for b in value[:30])
        if len(value) > 30:
            hex_part += " ..."
        return hex_part

    if mode == "text":
        try:
            decoded = value.decode("utf-8")
        except UnicodeDecodeError:
            return "двоичные данные"
        if not all(ch.isprintable() or ch.isspace() for ch in decoded):
            return "двоичные данные"
        if len(decoded) > 30:
            return decoded[:30] + "..."
        return decoded

    raise ValueError(f"Unknown mode {mode}")


def format_attribute_value_full_hex(value: bytes, bytes_per_line: int = 16):
    """Format attribute value as an iterable of hex lines without truncation."""

    if value is None:
        return None
    if len(value) == 0:
        return [""]
    lines = []
    for idx in range(0, len(value), bytes_per_line):
        chunk = value[idx : idx + bytes_per_line]
        lines.append(" ".join(f"{byte:02X}" for byte in chunk))
    return lines


def print_attribute_hex(name: str, raw_value: bytes, indent: str = "      ") -> None:
    """Print attribute value in HEX form with proper indentation."""

    label = f"{indent}{name} (HEX): "
    if raw_value is None:
        print(f"{label}—")
        return

    hex_lines = format_attribute_value_full_hex(raw_value)
    if not hex_lines:
        print(label.rstrip())
        return

    print(f"{label}{hex_lines[0]}")
    continuation = indent + " " * (len(name) + len(" (HEX): "))
    for line in hex_lines[1:]:
        print(f"{continuation}{line}")


def print_attribute_text(name: str, raw_value: bytes, indent: str = "      ") -> None:
    """Print attribute value in text form guarding against non-printables."""

    label = f"{indent}{name}: "
    if raw_value is None:
        print(f"{label}—")
        return

    text_value = format_attribute_value(raw_value, "text")

    print(f"{label}{text_value}")


def _decode_char_array(char_array) -> str:
    raw = bytes(char_array)
    text = raw.rstrip(b"\0 ").decode("utf-8", errors="ignore").strip()
    return text if text else "—"


def _format_version(version) -> str:
    return f"{version.major}.{version.minor}"


def _format_hex_bytes(data: bytes) -> str:
    if not data:
        return "—"
    return " ".join(f"{byte:02X}" for byte in data)


def _prepare_value(value) -> str:
    if value is None:
        return "—"
    if isinstance(value, str):
        return value if value else "—"
    return str(value)


def _zero_bytearray(buffer) -> None:
    if buffer is None:
        return
    for idx in range(len(buffer)):
        buffer[idx] = 0


def _print_table(title: str, rows, headers=("Параметр", "Значение")) -> None:
    if not rows:
        return
    print(title)
    col1_width = max(len(headers[0]), *(len(row[0]) for row in rows))
    col2_width = max(len(headers[1]), *(len(row[1]) for row in rows))
    print(f"{headers[0].ljust(col1_width)} | {headers[1].ljust(col2_width)}")
    print(f"{'-' * col1_width}-+-{'-' * col2_width}")
    for name, value in rows:
        print(f"{name.ljust(col1_width)} | {value}")
    print()


def safe_get_attributes(pkcs11, session, handle, attr_types):
    """Safely read a list of attributes for a PKCS#11 object.

    Returns a dictionary mapping attribute type to value. If the attributes
    cannot be retrieved (for example, because the handle is invalid), ``None``
    is returned instead of raising an exception or printing to stderr.
    """

    if handle is None:
        return None

    result = {}
    handle_obj = ctypes.c_ulong(handle)
    unavailable = ctypes.c_ulong(-1).value

    for attr_type in attr_types:
        attr_template = CK_ATTRIBUTE(type=attr_type, pValue=None, ulValueLen=0)
        rv = pkcs11.C_GetAttributeValue(
            session, handle_obj, ctypes.byref(attr_template), 1
        )
        if rv == CKR_OBJECT_HANDLE_INVALID:
            return None
        if rv != CKR_OK:
            continue

        length = attr_template.ulValueLen
        if length == unavailable:
            continue
        if length > 0:
            buffer = (ctypes.c_ubyte * length)()
            attr_template.pValue = ctypes.cast(buffer, ctypes.c_void_p)
            rv = pkcs11.C_GetAttributeValue(
                session, handle_obj, ctypes.byref(attr_template), 1
            )
            if rv == CKR_OBJECT_HANDLE_INVALID:
                return None
            if rv != CKR_OK:
                continue
            raw_value = bytes(buffer)
        else:
            raw_value = b""

        if attr_type == CKA_KEY_TYPE:
            if raw_value:
                result[attr_type] = int.from_bytes(raw_value, sys.byteorder)
        else:
            result[attr_type] = raw_value

    return result


def parse_hex_input(text: str) -> bytes:
    """Преобразовать строку с шестнадцатеричными данными в байты."""

    if text is None:
        raise ValueError("значение не указано")

    cleaned = text.strip()
    if not cleaned:
        raise ValueError("строка пуста")

    tokens = cleaned.split()
    normalized_parts = []

    if len(tokens) > 1:
        for token in tokens:
            part = token.strip()
            if part.lower().startswith("0x"):
                part = part[2:]
            if not part:
                raise ValueError("обнаружен пустой токен")
            if len(part) % 2 == 1:
                part = "0" + part
            normalized_parts.append(part)
        normalized = "".join(normalized_parts)
    else:
        token = tokens[0]
        if token.lower().startswith("0x") and token.lower().count("0x") == 1:
            token = token[2:]
        normalized = token.replace(" ", "")

    if not normalized:
        raise ValueError("строка пуста")
    if len(normalized) % 2 != 0:
        raise ValueError("нечётное количество символов")

    try:
        return bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError("значение содержит недопустимые символы") from exc


def compute_digest(pkcs11, session, mechanism_value, data: bytes):
    """Вычислить дайджест данных с помощью функций PKCS#11."""

    mechanism = CK_MECHANISM(
        mechanism=mechanism_value, pParameter=None, ulParameterLen=0
    )
    rv = pkcs11.C_DigestInit(session, ctypes.byref(mechanism))
    if rv != CKR_OK:
        print(f'C_DigestInit вернула ошибку: 0x{rv:08X}', file=sys.stderr)
        return None

    data_len = len(data)
    data_buffer = None
    data_ptr = None
    if data_len:
        data_buffer = (ctypes.c_ubyte * data_len).from_buffer_copy(data)
        data_ptr = ctypes.cast(data_buffer, ctypes.c_void_p)

    digest_len = ctypes.c_ulong(0)
    rv = pkcs11.C_Digest(session, data_ptr, data_len, None, ctypes.byref(digest_len))
    if rv != CKR_OK:
        print(f'C_Digest вернула ошибку: 0x{rv:08X}', file=sys.stderr)
        return None

    digest_buffer = (ctypes.c_ubyte * digest_len.value)()
    rv = pkcs11.C_Digest(
        session,
        data_ptr,
        data_len,
        ctypes.cast(digest_buffer, ctypes.c_void_p),
        ctypes.byref(digest_len),
    )
    if rv != CKR_OK:
        print(f'C_Digest вернула ошибку: 0x{rv:08X}', file=sys.stderr)
        return None

    return bytes(digest_buffer[: digest_len.value])


# Коды возврата команд. Их отдаёт run_command_*, а main.py передаёт в sys.exit.
EXIT_OK = 0
EXIT_ERROR = 1


@contextlib.contextmanager
def pkcs11_library(pkcs11):
    """C_Initialize на входе, C_Finalize на выходе.

    Отдаёт True, если библиотека поднялась, иначе False — сообщение уже напечатано.
    Нужен командам, которым сессия не требуется: сведения о библиотеке, слоты,
    список кошельков, информация о токене.
    """

    rv = pkcs11.C_Initialize(None)
    if rv != CKR_OK:
        print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
        yield False
        return

    try:
        yield True
    finally:
        pkcs11.C_Finalize(None)


@contextlib.contextmanager
def wallet_session(pkcs11, wallet_id, pin=None):
    """C_Initialize → C_OpenSession → C_Login и обратная раскрутка в конце.

    Отдаёт хэндл сессии; None означает, что дойти до конца не удалось и сообщение
    об этом уже напечатано.

    PIN передают команды, которым нечего проверять до входа. Если проверить надо —
    например, разобрать мнемоническую фразу и не тратить попытку ввода PIN-кода
    впустую, — сессию открывают без PIN, а входят через logged_in_user после
    проверок. Без PIN вход не выполняется вовсе: так работает --list-keys, который
    показывает только открытые ключи.
    """

    session = ctypes.c_ulong()
    initialized = False
    session_opened = False
    logged_in = False

    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
            yield None
            return
        initialized = True

        rv = pkcs11.C_OpenSession(
            wallet_id,
            CKF_SERIAL_SESSION | CKF_RW_SESSION,
            None,
            None,
            ctypes.byref(session),
        )
        if rv == CKR_TOKEN_NOT_PRESENT:
            print('Нет подключенного кошелька, подключите кошелек')
            yield None
            return
        if rv != CKR_OK:
            print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
            yield None
            return
        session_opened = True

        if pin:
            pin_bytes = pin.encode('utf-8')
            rv = pkcs11.C_Login(session, CKU_USER, pin_bytes, len(pin_bytes))
            if rv != CKR_OK:
                print(f'C_Login вернула ошибку: 0x{rv:08X}')
                yield None
                return
            logged_in = True

        yield session
    finally:
        if logged_in:
            pkcs11.C_Logout(session)
        if session_opened:
            pkcs11.C_CloseSession(session)
        if initialized:
            pkcs11.C_Finalize(None)


@contextlib.contextmanager
def logged_in_user(pkcs11, session, pin):
    """C_Login на входе, C_Logout на выходе.

    Отдаёт True, если вход выполнен, иначе False — сообщение уже напечатано.
    Нужен там, где до входа выполняются проверки: сессия уже открыта, а PIN
    предъявляется, только когда ясно, что команде есть что делать.
    """

    pin_bytes = pin.encode('utf-8')
    rv = pkcs11.C_Login(session, CKU_USER, pin_bytes, len(pin_bytes))
    if rv != CKR_OK:
        print(f'C_Login вернула ошибку: 0x{rv:08X}')
        yield False
        return

    try:
        yield True
    finally:
        pkcs11.C_Logout(session)


def find_objects(pkcs11, session, obj_class):
    """Найти на токене все объекты указанного класса и вернуть список их хэндлов.

    Список ключей, удаление и подпись перебирают объекты одинаково, поэтому поиск
    живёт здесь, а не внутри каждой из трёх команд.
    """

    handles = []
    class_val = ctypes.c_ulong(obj_class)
    template = (CK_ATTRIBUTE * 1)(
        CK_ATTRIBUTE(
            type=CKA_CLASS,
            pValue=ctypes.cast(ctypes.pointer(class_val), ctypes.c_void_p),
            ulValueLen=ctypes.sizeof(class_val),
        )
    )

    rv = pkcs11.C_FindObjectsInit(session, template, 1)
    if rv != CKR_OK:
        print(f'C_FindObjectsInit вернула ошибку: 0x{rv:08X}')
        return handles

    obj = ctypes.c_ulong()
    count = ctypes.c_ulong()
    while True:
        rv = pkcs11.C_FindObjects(session, ctypes.byref(obj), 1, ctypes.byref(count))
        if rv != CKR_OK:
            print(f'C_FindObjects вернула ошибку: 0x{rv:08X}')
            break
        if count.value == 0:
            break
        handles.append(obj.value)

    rv = pkcs11.C_FindObjectsFinal(session)
    if rv != CKR_OK:
        print(f'C_FindObjectsFinal вернула ошибку: 0x{rv:08X}')

    return handles


def sort_key_pairs(pairs):
    """Упорядочить пары ключей так, как их нумерует key-number.

    По CKA_ID, а при совпадении — по порядку обнаружения. Нумерация начинается с
    единицы. Список, удаление и подпись обязаны нумеровать одинаково, поэтому
    правило записано здесь один раз.
    """

    return sorted(
        enumerate(pairs), key=lambda item: ((item[1]['key_id'] or b''), item[0])
    )


@pkcs11_command
def show_wallet_info(pkcs11, wallet_id=0):
    """Получить подробную информацию о кошельке."""

    return run_command_show_wallet_info(pkcs11, wallet_id=wallet_id)


def run_command_show_wallet_info(pkcs11, wallet_id=0):
    define_pkcs11_functions(pkcs11)

    had_error = False
    with pkcs11_library(pkcs11) as library_ready:
        if not library_ready:
            return EXIT_ERROR

        token_info = CK_TOKEN_INFO()
        if not had_error:
            rv = pkcs11.C_GetTokenInfo(wallet_id, ctypes.byref(token_info))
            if rv == CKR_TOKEN_NOT_PRESENT:
                print('Нет подключенного кошелька, подключите кошелек')
                had_error = True
            elif rv != CKR_OK:
                print(f'C_GetTokenInfo вернула ошибку: 0x{rv:08X}')
                had_error = True

        extended_info = None
        if not had_error:
            if not hasattr(pkcs11, 'C_EX_GetTokenInfoExtended'):
                print('Расширенная функция C_EX_GetTokenInfoExtended недоступна в библиотеке')
                had_error = True
            else:
                extended_info = CK_TOKEN_INFO_EXTENDED()
                extended_info.ulSizeofThisStructure = ctypes.sizeof(
                    CK_TOKEN_INFO_EXTENDED
                )
                rv = pkcs11.C_EX_GetTokenInfoExtended(
                    wallet_id, ctypes.byref(extended_info)
                )
                if rv == CKR_TOKEN_NOT_PRESENT:
                    print('Нет подключенного кошелька, подключите кошелек')
                    had_error = True
                elif rv != CKR_OK:
                    print(
                        f'C_EX_GetTokenInfoExtended вернула ошибку: 0x{rv:08X}'
                    )
                    had_error = True

        if not had_error and extended_info is not None:
            basic_rows = [
                ('Метка', _decode_char_array(token_info.label)),
                ('Производитель', _decode_char_array(token_info.manufacturerID)),
                ('Модель', _decode_char_array(token_info.model)),
                ('Серийный номер', _decode_char_array(token_info.serialNumber)),
                ('Флаги (значение)', f"0x{token_info.flags:08X}"),
                ('Версия аппаратная', _format_version(token_info.hardwareVersion)),
                ('Версия прошивки', _format_version(token_info.firmwareVersion)),
            ]
            basic_rows = [(name, _prepare_value(value)) for name, value in basic_rows]

            pin_rows = [
                ('Макс. длина PIN (стандарт)', token_info.ulMaxPinLen),
                ('Мин. длина PIN (стандарт)', token_info.ulMinPinLen),
                ('Макс. длина PIN (пользователь)', extended_info.ulMaxUserPinLen),
                ('Мин. длина PIN (пользователь)', extended_info.ulMinUserPinLen),
                (
                    'Макс. число попыток (пользователь)',
                    extended_info.ulMaxUserRetryCount,
                ),
                (
                    'Осталось попыток (пользователь)',
                    extended_info.ulUserRetryCountLeft,
                ),
            ]
            pin_rows = [(name, _prepare_value(value)) for name, value in pin_rows]

            serial_be = bytes(extended_info.serialNumber)
            atr_bytes = bytes(extended_info.ATR)[: extended_info.ulATRLen]
            firmware_checksum = (
                'недоступно'
                if extended_info.flags & TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE
                else f"0x{extended_info.ulFirmwareChecksum:08X}"
            )
            if extended_info.flags & TOKEN_FLAGS_FW_CHECKSUM_INVALID:
                firmware_checksum += ' (некорректна)'

            device_rows = [
                ('Номер микропрограммы', extended_info.ulMicrocodeNumber),
                ('Номер заказа', extended_info.ulOrderNumber),
                ('Серийный номер (BE)', _format_hex_bytes(serial_be)),
                ('Всего памяти, байт', extended_info.ulTotalMemory),
                ('Свободно памяти, байт', extended_info.ulFreeMemory),
                ('ATR', _format_hex_bytes(atr_bytes)),
                ('Длина ATR', extended_info.ulATRLen),
                ('Напряжение батареи, мВ', extended_info.ulBatteryVoltage),
                ('Контрольная сумма прошивки', firmware_checksum),
            ]
            device_rows = [(name, _prepare_value(value)) for name, value in device_rows]

            flag_descriptions = [
                (TOKEN_FLAGS_USER_PIN_NOT_DEFAULT, 'Пользовательский PIN изменён'),
                (TOKEN_FLAGS_SUPPORT_JOURNAL, 'Поддерживается журнал'),
                (TOKEN_FLAGS_USER_PIN_UTF8, 'Пользовательский PIN в UTF-8'),
                (
                    TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE,
                    'Контрольная сумма недоступна',
                ),
                (
                    TOKEN_FLAGS_FW_CHECKSUM_INVALID,
                    'Контрольная сумма некорректна',
                ),
            ]
            flag_rows = []
            for mask, description in flag_descriptions:
                is_set = 'Да' if extended_info.flags & mask else 'Нет'
                flag_rows.append((description, is_set))

            _print_table('Основная информация о кошельке', basic_rows)
            _print_table('Параметры PIN-кода', pin_rows)
            _print_table('Информация об устройстве', device_rows)
            _print_table(
                'Расширенные флаги', flag_rows, headers=('Флаг', 'Установлен')
            )

    return EXIT_ERROR if had_error else EXIT_OK


@pkcs11_command
def library_info(pkcs11):
    return run_command_library_info(pkcs11)


def run_command_library_info(pkcs11):
    define_pkcs11_functions(pkcs11)

    with pkcs11_library(pkcs11) as library_ready:
        if not library_ready:
            return EXIT_ERROR

        info = CK_INFO()
        rv = pkcs11.C_GetInfo(ctypes.byref(info))
        if rv != CKR_OK:
            print(f'C_GetInfo вернула ошибку: 0x{rv:08X}')
            return EXIT_ERROR

        version = f'{info.cryptokiVersion.major}.{info.cryptokiVersion.minor}'
        libver = f'{info.libraryVersion.major}.{info.libraryVersion.minor}'
        manuf = info.manufacturerID.decode('utf-8', errors='ignore')
        desc = info.libraryDescription.decode('utf-8', errors='ignore')
        print('Информация о PKCS#11 библиотеке:')
        print(f'  Cryptoki Version:    {version}')
        print(f'  Library Description: {desc}')
        print(f'  Manufacturer ID:     {manuf}')
        print(f'  Library Version:     {libver}')

    return EXIT_OK


@pkcs11_command
def list_slots(pkcs11):
    """Выводит список доступных слотов."""
    return run_command_list_slots(pkcs11)


def run_command_list_slots(pkcs11):
    define_pkcs11_functions(pkcs11)

    with pkcs11_library(pkcs11) as library_ready:
        if not library_ready:
            return EXIT_ERROR

        count = ctypes.c_ulong()
        rv = pkcs11.C_GetSlotList(False, None, ctypes.byref(count))
        if rv != CKR_OK:
            print(f'C_GetSlotList вернула ошибку: 0x{rv:08X}')
            return EXIT_ERROR

        slots = (ctypes.c_ulong * count.value)()
        rv = pkcs11.C_GetSlotList(False, slots, ctypes.byref(count))
        if rv != CKR_OK:
            print(f'C_GetSlotList вернула ошибку: 0x{rv:08X}')
            return EXIT_ERROR

        print('Список доступных слотов:')
        for slot_id in slots:
            print(f'  Слот ID: {slot_id}')

    return EXIT_OK


@pkcs11_command
def list_wallets(pkcs11):
    """Выводит список доступных кошельков (токенов)."""
    return run_command_list_wallets(pkcs11)


def run_command_list_wallets(pkcs11):
    define_pkcs11_functions(pkcs11)

    with pkcs11_library(pkcs11) as library_ready:
        if not library_ready:
            return EXIT_ERROR

        count = ctypes.c_ulong()
        rv = pkcs11.C_GetSlotList(True, None, ctypes.byref(count))
        if rv != CKR_OK:
            print(f'C_GetSlotList вернула ошибку: 0x{rv:08X}')
            return EXIT_ERROR
        if count.value == 0:
            print('Нет подключенного кошелька, подключите кошелек')
            return EXIT_ERROR

        slots = (ctypes.c_ulong * count.value)()
        rv = pkcs11.C_GetSlotList(True, slots, ctypes.byref(count))
        if rv != CKR_OK:
            print(f'C_GetSlotList вернула ошибку: 0x{rv:08X}')
            return EXIT_ERROR

        print('Список доступных кошельков:')
        for slot_id in slots:
            token_info = CK_TOKEN_INFO()
            rv = pkcs11.C_GetTokenInfo(slot_id, ctypes.byref(token_info))
            if rv != CKR_OK:
                print(f'  Слот {slot_id} не содержит кошелька.')
                continue

            label = token_info.label.decode('utf-8', errors='ignore').strip()
            manufacturer = token_info.manufacturerID.decode(
                'utf-8', errors='ignore'
            ).strip()
            model = token_info.model.decode('utf-8', errors='ignore').strip()
            serial = token_info.serialNumber.decode('utf-8', errors='ignore').strip()
            print(f'  Кошелёк в слоте {slot_id}:')
            print(f'    Метка: {label}')
            print(f'    Производитель: {manufacturer}')
            print(f'    Модель: {model}')
            print(f'    Серийный номер: {serial}')

    return EXIT_OK

@pkcs11_command
def list_keys(pkcs11, wallet_id=0, pin=None):
    """Выводит список ключей. Если PIN не задан, показываются только публичные ключи."""
    return run_command_list_keys(pkcs11, wallet_id=wallet_id, pin=pin)


def run_command_list_keys(pkcs11, wallet_id=0, pin=None):
    define_pkcs11_functions(pkcs11)

    with wallet_session(pkcs11, wallet_id, pin) as session:
        if session is None:
            return EXIT_ERROR

        logged_in = bool(pin)
        if not logged_in:
            print('Закрытые ключи не отображаются без ввода PIN-кода')

        objects = []

        def collect_attributes(handle):
            attr_map = safe_get_attributes(
                pkcs11,
                session,
                handle,
                [
                    CKA_LABEL,
                    CKA_ID,
                    CKA_VALUE,
                    CKA_KEY_TYPE,
                    CKA_EC_PARAMS,
                    CKA_EC_POINT,
                    CKA_MODULUS,
                    CKA_PUBLIC_EXPONENT,
                    CKA_MODULUS_BITS,
                ],
            )
            if attr_map is None:
                return None

            result = {}
            if CKA_LABEL in attr_map and attr_map[CKA_LABEL] is not None:
                result['CKA_LABEL'] = attr_map[CKA_LABEL]
            if CKA_ID in attr_map and attr_map[CKA_ID] is not None:
                result['CKA_ID'] = attr_map[CKA_ID]
            if CKA_VALUE in attr_map and attr_map[CKA_VALUE] is not None:
                result['CKA_VALUE'] = attr_map[CKA_VALUE]
            if CKA_KEY_TYPE in attr_map and attr_map[CKA_KEY_TYPE] is not None:
                result['CKA_KEY_TYPE'] = attr_map[CKA_KEY_TYPE]
            if CKA_EC_PARAMS in attr_map and attr_map[CKA_EC_PARAMS] is not None:
                result['CKA_EC_PARAMS'] = attr_map[CKA_EC_PARAMS]
            if CKA_EC_POINT in attr_map and attr_map[CKA_EC_POINT] is not None:
                result['CKA_EC_POINT'] = attr_map[CKA_EC_POINT]
            if CKA_MODULUS in attr_map and attr_map[CKA_MODULUS] is not None:
                result['CKA_MODULUS'] = attr_map[CKA_MODULUS]
            if (
                CKA_PUBLIC_EXPONENT in attr_map
                and attr_map[CKA_PUBLIC_EXPONENT] is not None
            ):
                result['CKA_PUBLIC_EXPONENT'] = attr_map[CKA_PUBLIC_EXPONENT]
            if (
                CKA_MODULUS_BITS in attr_map
                and attr_map[CKA_MODULUS_BITS] is not None
            ):
                result['CKA_MODULUS_BITS'] = attr_map[CKA_MODULUS_BITS]

            return result

        def add_object(kind, handle, attrs, key_id_override=None):
            key_id = key_id_override
            if key_id is None and attrs and 'CKA_ID' in attrs:
                key_id = attrs['CKA_ID']
            for entry in objects:
                if entry['key_id'] == key_id and kind not in entry:
                    entry[kind] = (handle, attrs)
                    return entry
            entry = {'key_id': key_id, kind: (handle, attrs)}
            objects.append(entry)
            return entry

        public_attrs_by_handle = {}
        public_handles_by_id = {}
        public_order = []

        for handle in find_objects(pkcs11, session, CKO_PUBLIC_KEY):
            attrs = collect_attributes(handle)
            public_attrs_by_handle[handle] = attrs
            if attrs and 'CKA_ID' in attrs:
                public_handles_by_id.setdefault(attrs['CKA_ID'], []).append(handle)
            public_order.append(handle)
            add_object('public', handle, attrs)

        def find_public_key_by_id(key_id):
            if key_id is None:
                return None
            handles = public_handles_by_id.get(key_id)
            if not handles:
                return None
            return handles.pop(0)

        seen_public_handles = set()

        if logged_in:
            for handle in find_objects(pkcs11, session, CKO_PRIVATE_KEY):
                attrs = collect_attributes(handle)
                entry = add_object('private', handle, attrs)
                key_id = entry['key_id']
                if key_id is None and attrs and 'CKA_ID' in attrs:
                    key_id = attrs['CKA_ID']
                    entry['key_id'] = key_id

                pub_handle = None
                if attrs and 'CKA_ID' in attrs:
                    pub_handle = find_public_key_by_id(attrs['CKA_ID'])
                if pub_handle is not None:
                    seen_public_handles.add(pub_handle)
                    entry['public'] = (
                        pub_handle,
                        public_attrs_by_handle.get(pub_handle),
                    )
                elif 'public' in entry:
                    # keep previously collected public data if available
                    pass

        for handle in public_order:
            if handle in seen_public_handles:
                continue
            attrs = public_attrs_by_handle.get(handle)
            add_object('public', handle, attrs)

        print('Список ключей в кошельке:')
        sorted_pairs = sort_key_pairs(objects)
        for idx, pair in enumerate(sorted_pairs, start=1):
            pair = pair[1]
            key_type = None
            public_entry = pair.get('public')
            if (
                public_entry
                and public_entry[1] is not None
                and 'CKA_KEY_TYPE' in public_entry[1]
            ):
                key_type = public_entry[1]['CKA_KEY_TYPE']
            private_entry = pair.get('private')
            if key_type is None and private_entry and private_entry[1] and 'CKA_KEY_TYPE' in private_entry[1]:
                key_type = private_entry[1]['CKA_KEY_TYPE']
            suffix = (
                f" ({key_type_description.get(key_type)})"
                if key_type in key_type_description
                else ''
            )
            print(f'  Ключ \N{numero sign}{idx} (key-number={idx}){suffix}:')
            if public_entry and public_entry[1] is not None:
                _, attrs = public_entry
                print('    Открытый ключ')

                names_to_print = ['CKA_LABEL', 'CKA_ID']
                if key_type == CKK_GOSTR3410:
                    names_to_print.append('CKA_VALUE')
                elif key_type in {CKK_EC, CKK_EC_EDWARDS, CKK_EC_MONTGOMERY}:
                    names_to_print.extend(['CKA_EC_PARAMS', 'CKA_EC_POINT'])
                elif key_type == CKK_RSA:
                    names_to_print.extend(
                        ['CKA_MODULUS', 'CKA_PUBLIC_EXPONENT', 'CKA_MODULUS_BITS']
                    )
                elif 'CKA_VALUE' in attrs:
                    names_to_print.append('CKA_VALUE')

                for name in names_to_print:
                    raw = attrs.get(name)
                    if (
                        raw is None
                        and name == 'CKA_LABEL'
                        and private_entry
                        and private_entry[1]
                    ):
                        raw = private_entry[1].get(name)
                    if raw is not None:
                        if name in {'CKA_LABEL', 'CKA_ID'}:
                            print_attribute_text(name, raw)
                        print_attribute_hex(name, raw)
            else:
                print('  предупреждение: отсутствует открытый ключ')
            if 'private' in pair:
                _, attrs = pair['private']
                print('    Закрытый ключ')
                if attrs is not None:
                    private_names = ['CKA_LABEL', 'CKA_ID']
                    if key_type not in {
                        CKK_GOSTR3410,
                        CKK_EC,
                        CKK_EC_EDWARDS,
                        CKK_EC_MONTGOMERY,
                        CKK_RSA,
                    } and 'CKA_VALUE' in attrs:
                        private_names.append('CKA_VALUE')

                    for name in private_names:
                        if name in attrs:
                            if name in {'CKA_LABEL', 'CKA_ID'}:
                                print_attribute_text(name, attrs[name])
                            print_attribute_hex(name, attrs[name])
                else:
                    print('      не удалось прочитать атрибуты приватного ключа')

    return EXIT_OK


@pkcs11_command
def change_pin(pkcs11, wallet_id=0, old_pin=None, new_pin=None):
    """Сменить пользовательский PIN-код токена."""
    run_command_change_pin(
        pkcs11, wallet_id=wallet_id, old_pin=old_pin, new_pin=new_pin
    )


def run_command_change_pin(pkcs11, wallet_id=0, old_pin=None, new_pin=None):
    define_pkcs11_functions(pkcs11)

    session = ctypes.c_ulong()
    initialized = False
    session_opened = False
    logged_in = False
    had_error = False

    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
            had_error = True
        else:
            initialized = True

        if not had_error:
            rv = pkcs11.C_OpenSession(
                wallet_id,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None,
                None,
                ctypes.byref(session),
            )
            if rv == CKR_TOKEN_NOT_PRESENT:
                print('Нет подключенного кошелька, подключите кошелек')
                had_error = True
            elif rv != CKR_OK:
                print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                session_opened = True

        if session_opened:
            if old_pin is None or new_pin is None:
                print(
                    'Необходимо указать текущий и новый PIN-коды',
                    file=sys.stderr,
                )
                had_error = True
            else:
                old_pin_bytes = old_pin.encode('utf-8')
                new_pin_bytes = new_pin.encode('utf-8')

                rv = pkcs11.C_Login(
                    session, CKU_USER, old_pin_bytes, len(old_pin_bytes)
                )
                if rv != CKR_OK:
                    print(f'C_Login вернула ошибку: 0x{rv:08X}')
                    had_error = True
                else:
                    logged_in = True
                    rv = pkcs11.C_SetPIN(
                        session,
                        old_pin_bytes,
                        len(old_pin_bytes),
                        new_pin_bytes,
                        len(new_pin_bytes),
                    )
                    if rv != CKR_OK:
                        print(f'C_SetPIN вернула ошибку: 0x{rv:08X}')
                    else:
                        print('PIN-код успешно изменён.')
    finally:
        if logged_in:
            pkcs11.C_Logout(session)
        if session_opened:
            pkcs11.C_CloseSession(session)
        if initialized:
            pkcs11.C_Finalize(None)


@pkcs11_command
def import_keys(
    pkcs11,
    wallet_id=0,
    pin=None,
    mnemonic=None,
    cka_id="",
    cka_label="",
):
    """Импортировать master node HD-дерева по мнемонической фразе."""
    run_command_import_keys(
        pkcs11,
        wallet_id=wallet_id,
        pin=pin,
        mnemonic=mnemonic,
        cka_id=cka_id,
        cka_label=cka_label,
    )


def run_command_import_keys(
    pkcs11,
    wallet_id=0,
    pin=None,
    mnemonic=None,
    cka_id="",
    cka_label="",
):
    define_pkcs11_functions(pkcs11)

    session = ctypes.c_ulong()
    initialized = False
    session_opened = False
    logged_in = False
    had_error = False

    mnemonic_bytes = None
    seed = None
    hmac_result = None
    master_priv = None
    chain_code = None
    master_priv_buf = None
    chain_code_buf = None
    ec_params_buf = None
    id_buf = None
    label_buf = None

    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
            had_error = True
        else:
            initialized = True

        if not had_error:
            rv = pkcs11.C_OpenSession(
                wallet_id,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None,
                None,
                ctypes.byref(session),
            )
            if rv == CKR_TOKEN_NOT_PRESENT:
                print('Нет подключенного кошелька, подключите кошелек')
                had_error = True
            elif rv != CKR_OK:
                print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                session_opened = True

        if session_opened:
            if not pin:
                print(
                    'Необходимо указать PIN-код для импорта ключей',
                    file=sys.stderr,
                )
                had_error = True
            if mnemonic is None:
                print(
                    'Необходимо указать мнемоническую фразу для импорта ключей',
                    file=sys.stderr,
                )
                had_error = True

        if session_opened and not had_error:
            sanitized = " ".join(mnemonic.strip().split())
            if not sanitized:
                print('Мнемоническая фраза не должна быть пустой', file=sys.stderr)
                had_error = True
            else:
                words = sanitized.split(" ")
                if len(words) not in {12, 15, 18, 21, 24}:
                    print(
                        'Мнемоническая фраза должна содержать 12, 15, 18, 21 или 24 слова',
                        file=sys.stderr,
                    )
                    had_error = True
                else:
                    normalized = unicodedata.normalize("NFKD", sanitized)
                    mnemonic_bytes = bytearray(normalized.encode('utf-8'))
                    seed = bytearray(
                        hashlib.pbkdf2_hmac(
                            'sha512', mnemonic_bytes, b'mnemonic', 2048, dklen=64
                        )
                    )
                    hmac_result = bytearray(
                        hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
                    )
                    master_priv = bytearray(hmac_result[:32])
                    chain_code = bytearray(hmac_result[32:])

        if session_opened and not had_error:
            pin_bytes = pin.encode('utf-8')
            rv = pkcs11.C_Login(session, CKU_USER, pin_bytes, len(pin_bytes))
            if rv != CKR_OK:
                print(f'C_Login вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                logged_in = True

        if logged_in and not had_error:
            if len(master_priv) != 32 or len(chain_code) != 32:
                print('Некорректная длина master key или chain code', file=sys.stderr)
                had_error = True
            else:
                ck_true = ctypes.c_ubyte(1)
                cko_private_key = ctypes.c_ulong(CKO_PRIVATE_KEY)
                key_type = ctypes.c_ulong(CKK_VENDOR_BIP32)
                master_priv_buf = (ctypes.c_ubyte * len(master_priv))(*master_priv)
                chain_code_buf = (ctypes.c_ubyte * len(chain_code))(*chain_code)
                ec_params_buf = (ctypes.c_ubyte * len(SECP256K1_OID_DER))(
                    *SECP256K1_OID_DER
                )

                attributes = [
                    CK_ATTRIBUTE(
                        type=CKA_CLASS,
                        pValue=ctypes.cast(
                            ctypes.pointer(cko_private_key), ctypes.c_void_p
                        ),
                        ulValueLen=ctypes.sizeof(cko_private_key),
                    ),
                    CK_ATTRIBUTE(
                        type=CKA_KEY_TYPE,
                        pValue=ctypes.cast(ctypes.pointer(key_type), ctypes.c_void_p),
                        ulValueLen=ctypes.sizeof(key_type),
                    ),
                    CK_ATTRIBUTE(
                        type=CKA_VALUE,
                        pValue=ctypes.cast(master_priv_buf, ctypes.c_void_p),
                        ulValueLen=len(master_priv),
                    ),
                    CK_ATTRIBUTE(
                        type=CKA_VENDOR_BIP32_CHAINCODE,
                        pValue=ctypes.cast(chain_code_buf, ctypes.c_void_p),
                        ulValueLen=len(chain_code),
                    ),
                    CK_ATTRIBUTE(
                        type=CKA_TOKEN,
                        pValue=ctypes.cast(ctypes.pointer(ck_true), ctypes.c_void_p),
                        ulValueLen=1,
                    ),
                    CK_ATTRIBUTE(
                        type=CKA_PRIVATE,
                        pValue=ctypes.cast(ctypes.pointer(ck_true), ctypes.c_void_p),
                        ulValueLen=1,
                    ),
                    CK_ATTRIBUTE(
                        type=CKA_DERIVE,
                        pValue=ctypes.cast(ctypes.pointer(ck_true), ctypes.c_void_p),
                        ulValueLen=1,
                    ),
                    CK_ATTRIBUTE(
                        type=CKA_EC_PARAMS,
                        pValue=ctypes.cast(ec_params_buf, ctypes.c_void_p),
                        ulValueLen=len(SECP256K1_OID_DER),
                    ),
                ]

                if cka_id:
                    id_bytes = cka_id.encode('utf-8')
                    id_buf = (ctypes.c_ubyte * len(id_bytes))(*id_bytes)
                    attributes.append(
                        CK_ATTRIBUTE(
                            type=CKA_ID,
                            pValue=ctypes.cast(id_buf, ctypes.c_void_p),
                            ulValueLen=len(id_bytes),
                        )
                    )

                if cka_label:
                    label_bytes = cka_label.encode('utf-8')
                    label_buf = ctypes.create_string_buffer(label_bytes)
                    attributes.append(
                        CK_ATTRIBUTE(
                            type=CKA_LABEL,
                            pValue=ctypes.cast(label_buf, ctypes.c_void_p),
                            ulValueLen=len(label_bytes),
                        )
                    )

                private_template = (CK_ATTRIBUTE * len(attributes))(*attributes)
                handle = ctypes.c_ulong()
                rv = pkcs11.C_CreateObject(
                    session,
                    private_template,
                    len(attributes),
                    ctypes.byref(handle),
                )

                if rv != CKR_OK:
                    print(f'Ошибка создания объекта: 0x{rv:08X}')
                else:
                    print('Мастер-ключ успешно импортирован.')
    finally:
        if logged_in:
            pkcs11.C_Logout(session)
        if session_opened:
            pkcs11.C_CloseSession(session)
        if initialized:
            pkcs11.C_Finalize(None)

        _zero_bytearray(mnemonic_bytes)
        _zero_bytearray(seed)
        _zero_bytearray(hmac_result)
        _zero_bytearray(master_priv)
        _zero_bytearray(chain_code)

        if master_priv_buf is not None:
            ctypes.memset(master_priv_buf, 0, ctypes.sizeof(master_priv_buf))
        if chain_code_buf is not None:
            ctypes.memset(chain_code_buf, 0, ctypes.sizeof(chain_code_buf))
        if ec_params_buf is not None:
            ctypes.memset(ec_params_buf, 0, ctypes.sizeof(ec_params_buf))
        if id_buf is not None:
            ctypes.memset(id_buf, 0, ctypes.sizeof(id_buf))
        if label_buf is not None:
            ctypes.memset(label_buf, 0, ctypes.sizeof(label_buf))


@pkcs11_command
def generate_key_pair(
    pkcs11,
    wallet_id=0,
    pin=None,
    algorithm=None,
    cka_id="",
    cka_label="",
    get_mnemonic=False,
):
    """Generate key pair on token.

    Parameters
    ----------
    cka_id: str
        Value for the ``CKA_ID`` attribute.
    cka_label: str
        Value for the ``CKA_LABEL`` attribute.
    """
    run_command_generate_key_pair(
        pkcs11,
        wallet_id=wallet_id,
        pin=pin,
        algorithm=algorithm,
        cka_id=cka_id,
        cka_label=cka_label,
        get_mnemonic=get_mnemonic,
    )


def run_command_generate_key_pair(
    pkcs11,
    wallet_id=0,
    pin=None,
    algorithm=None,
    cka_id="",
    cka_label="",
    get_mnemonic=False,
):
    define_pkcs11_functions(pkcs11)

    session = ctypes.c_ulong()
    initialized = False
    session_opened = False
    logged_in = False
    had_error = False
    buffers = []

    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
            had_error = True
        else:
            initialized = True

        if not had_error:
            rv = pkcs11.C_OpenSession(
                wallet_id,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None,
                None,
                ctypes.byref(session),
            )
            if rv == CKR_TOKEN_NOT_PRESENT:
                print('Нет подключенного кошелька, подключите кошелек')
                had_error = True
            elif rv != CKR_OK:
                print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                session_opened = True

        if session_opened:
            if not cka_id or not cka_label:
                print(
                    'Необходимо указать key-id и key-label для генерации ключа',
                    file=sys.stderr,
                )
                had_error = True
            if not pin:
                print(
                    'Необходимо указать PIN-код для генерации ключа',
                    file=sys.stderr,
                )
                had_error = True
            if get_mnemonic and algorithm != 'secp256':
                print(
                    '--get-mnemonic доступен только для алгоритма secp256',
                    file=sys.stderr,
                )
                had_error = True
            if algorithm not in {'rsa1024', 'rsa2048', 'secp256', 'ed25519', 'gost'}:
                print('Неверный тип ключа')
                had_error = True

        if session_opened and not had_error:
            pin_bytes = pin.encode('utf-8')
            rv = pkcs11.C_Login(session, CKU_USER, pin_bytes, len(pin_bytes))
            if rv != CKR_OK:
                print(f'C_Login вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                logged_in = True

        mnemonic_attr = None
        if logged_in and not had_error:
            mechanism = CK_MECHANISM(mechanism=0, pParameter=None, ulParameterLen=0)

            true_val = ctypes.c_ubyte(1)
            false_val = ctypes.c_ubyte(0)

            pub_attrs = [
                CK_ATTRIBUTE(
                    type=CKA_TOKEN,
                    pValue=ctypes.cast(ctypes.pointer(true_val), ctypes.c_void_p),
                    ulValueLen=1,
                ),
                CK_ATTRIBUTE(
                    type=CKA_PRIVATE,
                    pValue=ctypes.cast(ctypes.pointer(false_val), ctypes.c_void_p),
                    ulValueLen=1,
                ),
            ]

            priv_attrs = [
                CK_ATTRIBUTE(
                    type=CKA_TOKEN,
                    pValue=ctypes.cast(ctypes.pointer(true_val), ctypes.c_void_p),
                    ulValueLen=1,
                ),
                CK_ATTRIBUTE(
                    type=CKA_PRIVATE,
                    pValue=ctypes.cast(ctypes.pointer(true_val), ctypes.c_void_p),
                    ulValueLen=1,
                ),
            ]

            if cka_id:
                id_bytes = cka_id.encode('utf-8')
                id_buf_pub = (ctypes.c_ubyte * len(id_bytes))(*id_bytes)
                id_buf_priv = (ctypes.c_ubyte * len(id_bytes))(*id_bytes)
                buffers.extend([id_buf_pub, id_buf_priv])
                pub_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_ID,
                        pValue=ctypes.cast(id_buf_pub, ctypes.c_void_p),
                        ulValueLen=len(id_bytes),
                    )
                )
                priv_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_ID,
                        pValue=ctypes.cast(id_buf_priv, ctypes.c_void_p),
                        ulValueLen=len(id_bytes),
                    )
                )

            if cka_label:
                label_bytes = cka_label.encode('utf-8')
                label_buf_pub = (ctypes.c_char * len(label_bytes)).from_buffer_copy(
                    label_bytes
                )
                label_buf_priv = (ctypes.c_char * len(label_bytes)).from_buffer_copy(
                    label_bytes
                )
                buffers.extend([label_buf_pub, label_buf_priv])
                pub_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_LABEL,
                        pValue=ctypes.cast(label_buf_pub, ctypes.c_void_p),
                        ulValueLen=len(label_bytes),
                    )
                )
                priv_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_LABEL,
                        pValue=ctypes.cast(label_buf_priv, ctypes.c_void_p),
                        ulValueLen=len(label_bytes),
                    )
                )

            if algorithm in {'rsa1024', 'rsa2048'}:
                mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN
                bits = 1024 if algorithm == 'rsa1024' else 2048
                bits_val = ctypes.c_ulong(bits)
                pub_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_MODULUS_BITS,
                        pValue=ctypes.cast(ctypes.pointer(bits_val), ctypes.c_void_p),
                        ulValueLen=ctypes.sizeof(bits_val),
                    )
                )
                exp = (ctypes.c_ubyte * 3)(0x01, 0x00, 0x01)
                pub_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_PUBLIC_EXPONENT,
                        pValue=ctypes.cast(exp, ctypes.c_void_p),
                        ulValueLen=3,
                    )
                )
            elif algorithm == 'secp256':
                if get_mnemonic:
                    mechanism.mechanism = CKM_VENDOR_BIP32_WITH_BIP39_KEY_PAIR_GEN
                    empty_passphrase = (ctypes.c_ubyte * 1)()
                    buffers.append(empty_passphrase)
                    mech_params = CK_VENDOR_BIP32_WITH_BIP39_KEY_PAIR_GEN_PARAMS()
                    mech_params.pPassphrase = ctypes.cast(
                        empty_passphrase, ctypes.c_void_p
                    )
                    mech_params.ulPassphraseLen = 0
                    mech_params.ulMnemonicLength = 24
                    buffers.append(mech_params)
                    mechanism.pParameter = ctypes.cast(
                        ctypes.pointer(mech_params), ctypes.c_void_p
                    )
                    mechanism.ulParameterLen = ctypes.sizeof(mech_params)
                else:
                    mechanism.mechanism = CKM_EC_KEY_PAIR_GEN
                    mechanism.pParameter = None
                    mechanism.ulParameterLen = 0
                oid = (ctypes.c_ubyte * len(SECP256K1_OID_DER))(*SECP256K1_OID_DER)
                pub_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_EC_PARAMS,
                        pValue=ctypes.cast(oid, ctypes.c_void_p),
                        ulValueLen=len(SECP256K1_OID_DER),
                    )
                )
                key_type_pub = ctypes.c_ulong(CKK_EC)
                key_type_priv = ctypes.c_ulong(CKK_EC)
                buffers.extend([key_type_pub, key_type_priv])
                pub_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_KEY_TYPE,
                        pValue=ctypes.cast(
                            ctypes.pointer(key_type_pub), ctypes.c_void_p
                        ),
                        ulValueLen=ctypes.sizeof(key_type_pub),
                    )
                )
                priv_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_KEY_TYPE,
                        pValue=ctypes.cast(
                            ctypes.pointer(key_type_priv), ctypes.c_void_p
                        ),
                        ulValueLen=ctypes.sizeof(key_type_priv),
                    )
                )
            elif algorithm == 'ed25519':
                mechanism.mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN
                oid = (ctypes.c_ubyte * 5)(0x06, 0x03, 0x2B, 0x65, 0x70)
                pub_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_EC_PARAMS,
                        pValue=ctypes.cast(oid, ctypes.c_void_p),
                        ulValueLen=5,
                    )
                )
            elif algorithm == 'gost':
                mechanism.mechanism = CKM_GOSTR3410_KEY_PAIR_GEN
                oid = (
                    ctypes.c_ubyte * 11
                )(0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01)
                pub_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_GOSTR3410_PARAMS,
                        pValue=ctypes.cast(oid, ctypes.c_void_p),
                        ulValueLen=11,
                    )
                )
                hash_oid = (
                    ctypes.c_ubyte * 10
                )(0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x02, 0x01)
                pub_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_GOSTR3411_PARAMS,
                        pValue=ctypes.cast(hash_oid, ctypes.c_void_p),
                        ulValueLen=10,
                    )
                )
                priv_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_GOSTR3411_PARAMS,
                        pValue=ctypes.cast(hash_oid, ctypes.c_void_p),
                        ulValueLen=10,
                    )
                )
                priv_attrs.append(
                    CK_ATTRIBUTE(
                        type=CKA_GOSTR3410_PARAMS,
                        pValue=ctypes.cast(oid, ctypes.c_void_p),
                        ulValueLen=11,
                    )
                )

            if get_mnemonic and algorithm == 'secp256':
                bip32_key_type = ctypes.c_ulong(CKK_VENDOR_BIP32)
                buffers.append(bip32_key_type)
                for attr_list in (pub_attrs, priv_attrs):
                    for attr in attr_list:
                        if attr.type == CKA_KEY_TYPE:
                            attr.pValue = ctypes.cast(
                                ctypes.pointer(bip32_key_type), ctypes.c_void_p
                            )
                            attr.ulValueLen = ctypes.sizeof(bip32_key_type)

            pub_template = (CK_ATTRIBUTE * len(pub_attrs))(*pub_attrs)
            priv_template = (CK_ATTRIBUTE * len(priv_attrs))(*priv_attrs)
            pub_handle = ctypes.c_ulong()
            priv_handle = ctypes.c_ulong()

            rv = pkcs11.C_GenerateKeyPair(
                session,
                ctypes.byref(mechanism),
                pub_template,
                len(pub_attrs),
                priv_template,
                len(priv_attrs),
                ctypes.byref(pub_handle),
                ctypes.byref(priv_handle),
            )

            if rv != CKR_OK:
                print(f'Ошибка генерации ключевой пары: 0x{rv:08X}')
            else:
                print('Ключевая пара успешно сгенерирована.')
                if get_mnemonic:
                    mnemonic_attr = CK_ATTRIBUTE(
                        type=CKA_VENDOR_BIP39_MNEMONIC,
                        pValue=None,
                        ulValueLen=0,
                    )
                    rv_attr = pkcs11.C_GetAttributeValue(
                        session,
                        priv_handle.value,
                        ctypes.byref(mnemonic_attr),
                        1,
                    )
                    if rv_attr != CKR_OK:
                        print(
                            f'Ошибка получения атрибута: 0x{rv_attr:08X}',
                            file=sys.stderr,
                        )
                    elif mnemonic_attr.ulValueLen == 0:
                        print(
                            'Мнемоническая фраза не возвращена токеном.',
                            file=sys.stderr,
                        )
                    else:
                        mnemonic_buf = (ctypes.c_char * mnemonic_attr.ulValueLen)()
                        mnemonic_attr.pValue = ctypes.cast(
                            mnemonic_buf, ctypes.c_void_p
                        )
                        rv_attr = pkcs11.C_GetAttributeValue(
                            session,
                            priv_handle.value,
                            ctypes.byref(mnemonic_attr),
                            1,
                        )
                        if rv_attr != CKR_OK:
                            print(
                                f'Ошибка получения атрибута: 0x{rv_attr:08X}',
                                file=sys.stderr,
                            )
                        else:
                            mnemonic_bytes = ctypes.string_at(
                                mnemonic_attr.pValue, mnemonic_attr.ulValueLen
                            )
                            mnemonic_text = mnemonic_bytes.decode(
                                'utf-8', errors='replace'
                            )
                            print("\n=============================================")
                            print(
                                'ЗАПИШИТЕ МНЕМОНИЧЕСКУЮ ФРАЗУ И СОХРАНИТЕ ЕЁ.'
                            )
                            print(
                                'ПОТЕРЯВ ФРАЗУ ВЫ НЕВОССТАНОВИМО ПОТЕРЯЕТЕ ДОСТУП К КЛЮЧАМ.\n'
                            )
                            print(mnemonic_text)
                            print('=============================================\n')

                            ck_false_local = ctypes.c_ubyte(0)
                            lock_attr = CK_ATTRIBUTE(
                                type=CKA_VENDOR_BIP39_MNEMONIC_IS_EXTRACTABLE,
                                pValue=ctypes.cast(
                                    ctypes.pointer(ck_false_local), ctypes.c_void_p
                                ),
                                ulValueLen=1,
                            )
                            rv_lock = pkcs11.C_SetAttributeValue(
                                session,
                                priv_handle.value,
                                ctypes.byref(lock_attr),
                                1,
                            )
                            if rv_lock != CKR_OK:
                                print(
                                    f'Ошибка установки атрибутов: 0x{rv_lock:08X}',
                                    file=sys.stderr,
                                )

                            ctypes.memset(
                                mnemonic_attr.pValue, 0, mnemonic_attr.ulValueLen
                            )
    finally:
        if logged_in:
            pkcs11.C_Logout(session)
        if session_opened:
            pkcs11.C_CloseSession(session)
        if initialized:
            pkcs11.C_Finalize(None)


@pkcs11_command
def delete_key_pair(pkcs11, wallet_id=0, pin=None, key_number=None, force=False):
    """Delete key pair from token by its index (``key-number``).

    Parameters
    ----------
    force: bool
        When ``True`` deletes all objects from the token instead of a specific
        key pair. ``force`` cannot be used together with ``key_number`` and
        requires a PIN code to be provided.
    """
    run_command_delete_key_pair(
        pkcs11,
        wallet_id=wallet_id,
        pin=pin,
        key_number=key_number,
        force=force,
    )


def run_command_delete_key_pair(
    pkcs11, wallet_id=0, pin=None, key_number=None, force=False
):
    define_pkcs11_functions(pkcs11)

    session = ctypes.c_ulong()
    initialized = False
    session_opened = False
    logged_in = False
    had_error = False

    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
            had_error = True
        else:
            initialized = True

        if not had_error:
            rv = pkcs11.C_OpenSession(
                wallet_id,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None,
                None,
                ctypes.byref(session),
            )
            if rv == CKR_TOKEN_NOT_PRESENT:
                print('Нет подключенного кошелька, подключите кошелек')
                had_error = True
            elif rv != CKR_OK:
                print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                session_opened = True

        if session_opened:
            if not pin:
                print('Необходимо указать PIN-код для удаления ключей', file=sys.stderr)
                had_error = True
            if force and key_number is not None:
                print(
                    'Параметры --force и --key-number не могут использоваться одновременно',
                    file=sys.stderr,
                )
                had_error = True
            if not force and key_number is None:
                print(
                    'Необходимо указать параметр --key-number для удаления ключа',
                    file=sys.stderr,
                )
                had_error = True

        if session_opened and not had_error:
            pin_bytes = pin.encode('utf-8')
            rv = pkcs11.C_Login(session, CKU_USER, pin_bytes, len(pin_bytes))
            if rv != CKR_OK:
                print(f'C_Login вернула ошибку: 0x{rv:08X}')
                had_error = True
            else:
                logged_in = True

        if logged_in and not had_error:

            def search_objects(obj_class):
                handles = []
                class_val = ctypes.c_ulong(obj_class)
                attr = CK_ATTRIBUTE(
                    type=CKA_CLASS,
                    pValue=ctypes.cast(ctypes.pointer(class_val), ctypes.c_void_p),
                    ulValueLen=ctypes.sizeof(class_val),
                )
                template = (CK_ATTRIBUTE * 1)(attr)
                rv_local = pkcs11.C_FindObjectsInit(session, template, 1)
                if rv_local != CKR_OK:
                    print(f'C_FindObjectsInit вернула ошибку: 0x{rv_local:08X}')
                    return handles

                obj = ctypes.c_ulong()
                count = ctypes.c_ulong()
                while True:
                    rv_local = pkcs11.C_FindObjects(
                        session, ctypes.byref(obj), 1, ctypes.byref(count)
                    )
                    if rv_local != CKR_OK:
                        print(f'C_FindObjects вернула ошибку: 0x{rv_local:08X}')
                        break
                    if count.value == 0:
                        break
                    handles.append(obj.value)

                rv_final = pkcs11.C_FindObjectsFinal(session)
                if rv_final != CKR_OK:
                    print(f'C_FindObjectsFinal вернула ошибку: 0x{rv_final:08X}')

                return handles

            def get_id(handle):
                attr = CK_ATTRIBUTE(type=CKA_ID, pValue=None, ulValueLen=0)
                rv_local = pkcs11.C_GetAttributeValue(
                    session, ctypes.c_ulong(handle), ctypes.byref(attr), 1
                )
                if rv_local != CKR_OK:
                    print(f'Ошибка получения атрибута: 0x{rv_local:08X}', file=sys.stderr)
                    return None
                if attr.ulValueLen == 0:
                    return None
                buf = (ctypes.c_ubyte * attr.ulValueLen)()
                attr.pValue = ctypes.cast(buf, ctypes.c_void_p)
                rv_local = pkcs11.C_GetAttributeValue(
                    session, ctypes.c_ulong(handle), ctypes.byref(attr), 1
                )
                if rv_local != CKR_OK:
                    print(f'Ошибка получения атрибута: 0x{rv_local:08X}', file=sys.stderr)
                    return None
                return bytes(buf)

            if force:
                handles_to_delete = []
                rv_local = pkcs11.C_FindObjectsInit(session, None, 0)
                if rv_local != CKR_OK:
                    print(f'C_FindObjectsInit вернула ошибку: 0x{rv_local:08X}')
                else:
                    try:
                        obj = ctypes.c_ulong()
                        count = ctypes.c_ulong()
                        while True:
                            rv_local = pkcs11.C_FindObjects(
                                session, ctypes.byref(obj), 1, ctypes.byref(count)
                            )
                            if rv_local != CKR_OK:
                                print(
                                    f'C_FindObjects вернула ошибку: 0x{rv_local:08X}'
                                )
                                break
                            if count.value == 0:
                                break
                            handles_to_delete.append(obj.value)
                    finally:
                        rv_final = pkcs11.C_FindObjectsFinal(session)
                        if rv_final != CKR_OK:
                            print(
                                f'C_FindObjectsFinal вернула ошибку: 0x{rv_final:08X}'
                            )

                for handle_value in handles_to_delete:
                    rv_local = pkcs11.C_DestroyObject(session, ctypes.c_ulong(handle_value))
                    if rv_local not in (CKR_OK, CKR_OBJECT_HANDLE_INVALID):
                        print(f'Ошибка удаления объекта: 0x{rv_local:08X}')
            else:
                pairs = []

                def add_handle(kind, handle):
                    key_id = get_id(handle)
                    for entry in pairs:
                        if entry['key_id'] == key_id and kind not in entry:
                            entry[kind] = handle
                            return
                    pairs.append({'key_id': key_id, kind: handle})

                for h in find_objects(pkcs11, session, CKO_PUBLIC_KEY):
                    add_handle('public', h)

                for h in find_objects(pkcs11, session, CKO_PRIVATE_KEY):
                    add_handle('private', h)

                sorted_pairs = sorted(
                    enumerate(pairs),
                    key=lambda item: ((item[1]['key_id'] or b''), item[0]),
                )

                if key_number < 1 or key_number > len(sorted_pairs):
                    print('Ключ с таким номером не найден')
                else:
                    pair = sorted_pairs[key_number - 1][1]
                    handles_to_delete = []
                    if 'private' in pair:
                        handles_to_delete.append(pair['private'])
                    if 'public' in pair:
                        handles_to_delete.append(pair['public'])
                    for handle_value in handles_to_delete:
                        rv_local = pkcs11.C_DestroyObject(
                            session, ctypes.c_ulong(handle_value)
                        )
                        if rv_local not in (CKR_OK, CKR_OBJECT_HANDLE_INVALID):
                            print(f'Ошибка удаления объекта: 0x{rv_local:08X}')
    finally:
        if logged_in:
            pkcs11.C_Logout(session)
        if session_opened:
            pkcs11.C_CloseSession(session)
        if initialized:
            pkcs11.C_Finalize(None)


@pkcs11_command
def sign(
    pkcs11,
    wallet_id=0,
    pin=None,
    key_number=None,
    hash_value=None,
    data=None,
):
    """Подписать данные приватным ключом, выбранным по ``key-number``."""

    run_command_sign(
        pkcs11,
        wallet_id=wallet_id,
        pin=pin,
        key_number=key_number,
        hash_value=hash_value,
        data=data,
    )


def run_command_sign(
    pkcs11,
    wallet_id=0,
    pin=None,
    key_number=None,
    hash_value=None,
    data=None,
):
    define_pkcs11_functions(pkcs11)

    if key_number is None:
        print(
            'Для подписи необходимо указать параметр --key-number',
            file=sys.stderr,
        )
        return

    if not pin:
        print('Необходимо указать PIN-код для выполнения подписи', file=sys.stderr)
        return

    if (hash_value is None and data is None) or (
        hash_value is not None and data is not None
    ):
        print(
            'Нужно указать ровно один из параметров --hash или --data',
            file=sys.stderr,
        )
        return

    session = ctypes.c_ulong()
    initialized = False
    session_opened = False
    logged_in = False
    try:
        rv = pkcs11.C_Initialize(None)
        if rv != CKR_OK:
            print(f'C_Initialize вернула ошибку: 0x{rv:08X}')
            return
        initialized = True

        rv = pkcs11.C_OpenSession(
            wallet_id,
            CKF_SERIAL_SESSION | CKF_RW_SESSION,
            None,
            None,
            ctypes.byref(session),
        )
        if rv == CKR_TOKEN_NOT_PRESENT:
            print('Нет подключенного кошелька, подключите кошелек')
            return
        if rv != CKR_OK:
            print(f'C_OpenSession вернула ошибку: 0x{rv:08X}')
            return
        session_opened = True

        pin_bytes = pin.encode('utf-8')
        rv = pkcs11.C_Login(session, CKU_USER, pin_bytes, len(pin_bytes))
        if rv != CKR_OK:
            print(f'C_Login вернула ошибку: 0x{rv:08X}')
            return
        logged_in = True

        def search_objects(obj_class):
            handles = []
            class_val = ctypes.c_ulong(obj_class)
            template = (CK_ATTRIBUTE * 1)(
                CK_ATTRIBUTE(
                    type=CKA_CLASS,
                    pValue=ctypes.cast(ctypes.pointer(class_val), ctypes.c_void_p),
                    ulValueLen=ctypes.sizeof(class_val),
                )
            )
            rv_local = pkcs11.C_FindObjectsInit(session, template, 1)
            if rv_local != CKR_OK:
                print(f'C_FindObjectsInit вернула ошибку: 0x{rv_local:08X}')
                return handles

            try:
                obj = ctypes.c_ulong()
                count = ctypes.c_ulong()
                while True:
                    rv_local = pkcs11.C_FindObjects(
                        session, ctypes.byref(obj), 1, ctypes.byref(count)
                    )
                    if rv_local != CKR_OK:
                        print(f'C_FindObjects вернула ошибку: 0x{rv_local:08X}')
                        break
                    if count.value == 0:
                        break
                    handles.append(obj.value)
            finally:
                rv_final = pkcs11.C_FindObjectsFinal(session)
                if rv_final != CKR_OK:
                    print(f'C_FindObjectsFinal вернула ошибку: 0x{rv_final:08X}')

            return handles

        def get_id(handle):
            attr = CK_ATTRIBUTE(type=CKA_ID, pValue=None, ulValueLen=0)
            rv_local = pkcs11.C_GetAttributeValue(
                session, ctypes.c_ulong(handle), ctypes.byref(attr), 1
            )
            if rv_local != CKR_OK:
                return None
            if attr.ulValueLen == 0:
                return None
            buf = (ctypes.c_ubyte * attr.ulValueLen)()
            attr.pValue = ctypes.cast(buf, ctypes.c_void_p)
            rv_local = pkcs11.C_GetAttributeValue(
                session, ctypes.c_ulong(handle), ctypes.byref(attr), 1
            )
            if rv_local != CKR_OK:
                return None
            return bytes(buf)

        pairs = []

        def add_handle(kind, handle):
            key_id = get_id(handle)
            for entry in pairs:
                if entry['key_id'] == key_id and kind not in entry:
                    entry[kind] = handle
                    return
            pairs.append({'key_id': key_id, kind: handle})

        for h in find_objects(pkcs11, session, CKO_PUBLIC_KEY):
            add_handle('public', h)

        for h in find_objects(pkcs11, session, CKO_PRIVATE_KEY):
            add_handle('private', h)

        sorted_pairs = sorted(
            enumerate(pairs), key=lambda item: ((item[1]['key_id'] or b''), item[0])
        )

        if key_number < 1 or key_number > len(sorted_pairs):
            print('Ключ с таким номером не найден', file=sys.stderr)
            return

        pair = sorted_pairs[key_number - 1][1]
        if 'private' not in pair:
            print('Для выбранного номера не найден приватный ключ', file=sys.stderr)
            return

        private_handle = pair['private']

        attrs = safe_get_attributes(
            pkcs11,
            session,
            private_handle,
            [CKA_KEY_TYPE],
        )
        key_type = None
        if attrs and CKA_KEY_TYPE in attrs:
            key_type = attrs[CKA_KEY_TYPE]
        elif 'public' in pair:
            public_attrs = safe_get_attributes(
                pkcs11,
                session,
                pair['public'],
                [CKA_KEY_TYPE],
            )
            if public_attrs and CKA_KEY_TYPE in public_attrs:
                key_type = public_attrs[CKA_KEY_TYPE]

        if key_type is None or key_type not in SIGN_KEY_CONFIG:
            print(
                'Подпись для данного типа ключа не поддерживается',
                file=sys.stderr,
            )
            return

        config = SIGN_KEY_CONFIG[key_type]
        digest_bytes = None

        if hash_value is not None:
            try:
                digest_bytes = parse_hex_input(hash_value)
            except ValueError as exc:
                print(f'Некорректное значение параметра --hash: {exc}', file=sys.stderr)
                return
            expected_len = config.get('hash_length')
            if expected_len and len(digest_bytes) != expected_len:
                print(
                    f'Хэш должен содержать {expected_len} байт для данного ключа',
                    file=sys.stderr,
                )
                return
        else:
            digest_mechanism = config.get('digest_mechanism')
            if digest_mechanism is None:
                print(
                    'Невозможно автоматически вычислить хэш для данного типа ключа',
                    file=sys.stderr,
                )
                return
            data_bytes = data.encode('utf-8') if data is not None else b''
            digest_bytes = compute_digest(pkcs11, session, digest_mechanism, data_bytes)
            if digest_bytes is None:
                return
            expected_len = config.get('hash_length')
            if expected_len and len(digest_bytes) != expected_len:
                print(
                    f'Полученный хэш имеет длину {len(digest_bytes)} байт, '
                    f'ожидалось {expected_len}',
                    file=sys.stderr,
                )
                return

        data_to_sign = digest_bytes
        if key_type == CKK_RSA:
            prefix = config.get('rsa_digest_info_prefix')
            if prefix is None:
                print('Неизвестный формат DigestInfo для RSA', file=sys.stderr)
                return
            data_to_sign = prefix + digest_bytes

        mechanism = CK_MECHANISM(
            mechanism=config['sign_mechanism'],
            pParameter=None,
            ulParameterLen=0,
        )
        rv = pkcs11.C_SignInit(
            session,
            ctypes.byref(mechanism),
            ctypes.c_ulong(private_handle),
        )
        if rv != CKR_OK:
            print(f'C_SignInit вернула ошибку: 0x{rv:08X}')
            return

        data_len = len(data_to_sign)
        data_buffer = (ctypes.c_ubyte * data_len).from_buffer_copy(data_to_sign)
        data_ptr = ctypes.cast(data_buffer, ctypes.c_void_p)
        signature_len = ctypes.c_ulong(0)

        rv = pkcs11.C_Sign(
            session,
            data_ptr,
            data_len,
            None,
            ctypes.byref(signature_len),
        )
        if rv != CKR_OK:
            print(f'C_Sign вернула ошибку: 0x{rv:08X}')
            return

        signature_buffer = (ctypes.c_ubyte * signature_len.value)()
        rv = pkcs11.C_Sign(
            session,
            data_ptr,
            data_len,
            ctypes.cast(signature_buffer, ctypes.c_void_p),
            ctypes.byref(signature_len),
        )
        if rv != CKR_OK:
            print(f'C_Sign вернула ошибку: 0x{rv:08X}')
            return

        digest_hex = digest_bytes.hex().upper()
        signature = bytes(signature_buffer[: signature_len.value])
        signature_hex = signature.hex().upper()

        print('Хэш (HEX):', digest_hex)
        print('Подпись (HEX):', signature_hex)

    finally:
        if logged_in:
            pkcs11.C_Logout(session)
        if session_opened:
            pkcs11.C_CloseSession(session)
        if initialized:
            pkcs11.C_Finalize(None)
