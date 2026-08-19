import ctypes
import hashlib
import hmac
import os
import sys
import unicodedata
from types import SimpleNamespace

import pytest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import commands
import pkcs11
import pkcs11_structs as structs

# OID кривой secp256k1 (1.3.132.0.10) в DER — сверяем литералом, а не константой
# из commands.py, иначе проверка пройдёт при любом её значении.
SECP256K1_OID_DER = bytes((0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A))


def test_list_keys_public_only_no_pin(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 123
        return 0
    pkcs11_mock.C_OpenSession = open_session

    login_args = []
    def login(*args):
        login_args.append(args)
        return 0
    pkcs11_mock.C_Login = login

    captured = []

    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attr = arr[0]
        val_ptr = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong))
        captured.append(val_ptr.contents.value)
        return 0
    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        count_ptr._obj.value = 0
        return 0
    pkcs11_mock.C_FindObjects = find_objects

    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0
    pkcs11_mock.C_GetAttributeValue = lambda *args: 0
    logout_called = []
    pkcs11_mock.C_Logout = lambda session: logout_called.append(True) or 0

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_keys(wallet_id=1, pin=None)

    out = capsys.readouterr().out
    assert "Закрытые ключи не отображаются" in out
    assert login_args == []
    assert captured == [structs.CKO_PUBLIC_KEY]
    assert logout_called == []


def test_library_info_prints_wallet_description(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()
    expected_desc = "Rutoken Wallet PKCS #11 library"

    def get_info(info_ptr):
        info = ctypes.cast(info_ptr, ctypes.POINTER(structs.CK_INFO)).contents
        info.cryptokiVersion.major = 2
        info.cryptokiVersion.minor = 40
        info.libraryVersion.major = 3
        info.libraryVersion.minor = 20
        info.manufacturerID = b"Aktiv".ljust(len(info.manufacturerID), b"\0")
        info.libraryDescription = expected_desc.encode("utf-8").ljust(
            len(info.libraryDescription),
            b"\0",
        )
        return 0

    pkcs11_mock.C_GetInfo = get_info

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.library_info()

    out = capsys.readouterr().out
    assert expected_desc in out


def test_list_keys_with_pin_search_templates(monkeypatch):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 123
        return 0
    pkcs11_mock.C_OpenSession = open_session

    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0
    pkcs11_mock.C_GetAttributeValue = lambda *args: 0
    logout_called = []
    pkcs11_mock.C_Logout = lambda session: logout_called.append(True) or 0

    calls = []
    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attr = arr[0]
        val_ptr = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong))
        calls.append(val_ptr.contents.value)
        return 0
    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        count_ptr._obj.value = 0
        return 0
    pkcs11_mock.C_FindObjects = find_objects

    login_args = []
    def login(*args):
        login_args.append(args)
        return 0
    pkcs11_mock.C_Login = login

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_keys(wallet_id=1, pin="0000")

    assert len(login_args) == 1
    assert login_args[0][1] == structs.CKU_USER
    assert set(calls) == {structs.CKO_PUBLIC_KEY, structs.CKO_PRIVATE_KEY}
    assert logout_called == [True]


def test_list_wallets_no_wallet(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()

    def get_slot_list(token_present, slot_list, count_ptr):
        count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_GetSlotList = get_slot_list

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_wallets()

    captured = capsys.readouterr()
    assert "Нет подключенного кошелька" in captured.out


def test_show_wallet_info_prints_tables(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()

    def get_token_info(slot, info_ptr):
        info = ctypes.cast(info_ptr, ctypes.POINTER(structs.CK_TOKEN_INFO)).contents
        info.label = b"Wallet".ljust(32, b"\0")
        info.manufacturerID = b"Aktiv".ljust(32, b" ")
        info.model = b"Model".ljust(16, b" ")
        info.serialNumber = b"1234567890123456"
        info.flags = 0x1234
        info.hardwareVersion.major = 1
        info.hardwareVersion.minor = 2
        info.firmwareVersion.major = 3
        info.firmwareVersion.minor = 4
        info.ulMaxPinLen = 12
        info.ulMinPinLen = 4
        return 0

    pkcs11_mock.C_GetTokenInfo = get_token_info

    def get_token_info_extended(slot, info_ptr):
        info = ctypes.cast(info_ptr, ctypes.POINTER(structs.CK_TOKEN_INFO_EXTENDED)).contents
        assert info.ulSizeofThisStructure == ctypes.sizeof(structs.CK_TOKEN_INFO_EXTENDED)
        info.ulMicrocodeNumber = 101
        info.ulOrderNumber = 202
        info.flags = (
            structs.TOKEN_FLAGS_USER_PIN_NOT_DEFAULT
            | structs.TOKEN_FLAGS_SUPPORT_JOURNAL
            | structs.TOKEN_FLAGS_FW_CHECKSUM_INVALID
        )
        info.ulMaxUserPinLen = 16
        info.ulMinUserPinLen = 6
        info.ulMaxUserRetryCount = 5
        info.ulUserRetryCountLeft = 3
        info.serialNumber[:] = (1, 2, 3, 4, 5, 6, 7, 8)
        info.ulTotalMemory = 4096
        info.ulFreeMemory = 1024
        atr = bytes(range(4))
        for idx, value in enumerate(atr):
            info.ATR[idx] = value
        info.ulATRLen = len(atr)
        info.ulBatteryVoltage = 3000
        info.ulFirmwareChecksum = 0xABCDEF01
        return 0

    pkcs11_mock.C_EX_GetTokenInfoExtended = get_token_info_extended

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.show_wallet_info(wallet_id=1)

    out = capsys.readouterr().out
    assert "Основная информация о кошельке" in out
    assert "Метка" in out and "Wallet" in out
    assert "Параметры PIN-кода" in out
    assert "Макс. длина PIN (пользователь)" in out
    assert "Информация об устройстве" in out
    assert "Номер микропрограммы" in out
    assert "Расширенные флаги" in out
    flag_line = next(line for line in out.splitlines() if "Поддерживается журнал" in line)
    assert flag_line.strip().endswith("| Да")
    assert "Контрольная сумма некорректна" in out


def test_show_wallet_info_no_token(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()
    pkcs11_mock.C_GetTokenInfo = lambda slot, info: structs.CKR_TOKEN_NOT_PRESENT

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.show_wallet_info(wallet_id=0)

    out = capsys.readouterr().out
    assert "Нет подключенного кошелька" in out


def test_list_keys_no_wallet(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()
    pkcs11_mock.C_OpenSession = lambda *args: structs.CKR_TOKEN_NOT_PRESENT

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_keys(wallet_id=1, pin="0000")

    captured = capsys.readouterr()
    assert "Нет подключенного кошелька" in captured.out


def test_format_attribute_value_text():
    data = b"hello"
    assert commands.format_attribute_value(data, "text") == "hello"


def test_format_attribute_value_binary_text():
    data = b"\x00\x01\x02"
    assert commands.format_attribute_value(data, "text") == "двоичные данные"


def test_format_attribute_value_hex_truncate():
    data = bytes(range(40))
    out = commands.format_attribute_value(data, "hex")
    assert out.startswith("00 01 02")
    assert out.endswith("...")


def test_format_attribute_value_text_truncate():
    data = b"a" * 40
    out = commands.format_attribute_value(data, "text")
    assert out == "a" * 30 + "..."


def test_list_keys_prints_key_type(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0

    pkcs11_mock.C_OpenSession = open_session

    def find_objects_init(session_handle, template_ptr, count):
        return 0

    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        if not hasattr(find_objects, "done"):
            obj_ptr._obj.value = 42
            count_ptr._obj.value = 1
            find_objects.done = True
        else:
            count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0
    logout_called = []
    pkcs11_mock.C_Logout = lambda session: logout_called.append(True) or 0

    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        if not attr.pValue:
            if attr.type == structs.CKA_KEY_TYPE:
                attr.ulValueLen = ctypes.sizeof(ctypes.c_ulong)
            else:
                attr.ulValueLen = 0
            return 0
        if attr.type == structs.CKA_KEY_TYPE:
            val = ctypes.c_ulong(structs.CKK_RSA)
            ctypes.memmove(attr.pValue, ctypes.byref(val), ctypes.sizeof(val))
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attribute_value

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_keys(wallet_id=1, pin=None)

    out = capsys.readouterr().out
    assert "RSA" in out


def test_list_keys_prints_ec_key_type(monkeypatch, capsys):
    """Simulate object with EC key type and expect ECDSA description."""
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0

    pkcs11_mock.C_OpenSession = open_session
    pkcs11_mock.C_FindObjectsInit = lambda *args: 0

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        if not hasattr(find_objects, "done"):
            obj_ptr._obj.value = 55
            count_ptr._obj.value = 1
            find_objects.done = True
        else:
            count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0

    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        if not attr.pValue:
            if attr.type == structs.CKA_KEY_TYPE:
                attr.ulValueLen = ctypes.sizeof(ctypes.c_ulong)
            else:
                attr.ulValueLen = 0
            return 0
        if attr.type == structs.CKA_KEY_TYPE:
            val = ctypes.c_ulong(structs.CKK_EC)
            ctypes.memmove(attr.pValue, ctypes.byref(val), ctypes.sizeof(val))
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attribute_value

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_keys(wallet_id=1, pin=None)

    out = capsys.readouterr().out
    assert "ECDSA" in out
    assert "bitcoin" in out


def test_list_keys_gost_value_full_hex(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0

    pkcs11_mock.C_OpenSession = open_session

    current_class = None

    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attr = arr[0]
        val_ptr = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong))
        nonlocal current_class
        current_class = val_ptr.contents.value
        return 0

    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        if (
            current_class == structs.CKO_PUBLIC_KEY
            and not hasattr(find_objects, "pub_done")
        ):
            obj_ptr._obj.value = 200
            count_ptr._obj.value = 1
            find_objects.pub_done = True
        else:
            count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0

    attr_map = {
        200: {
            structs.CKA_LABEL: b"gost",
            structs.CKA_ID: b"id",
            structs.CKA_VALUE: bytes(range(32)),
            structs.CKA_KEY_TYPE: structs.CKK_GOSTR3410,
        }
    }

    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        handle = obj if isinstance(obj, int) else obj.value
        data = attr_map.get(handle, {})

        if not attr.pValue:
            if attr.type == structs.CKA_KEY_TYPE:
                attr.ulValueLen = ctypes.sizeof(ctypes.c_ulong)
            elif attr.type in data:
                attr.ulValueLen = len(data[attr.type])
            else:
                attr.ulValueLen = 0
            return 0

        if attr.type == structs.CKA_KEY_TYPE:
            val = ctypes.c_ulong(data.get(attr.type, 0))
            ctypes.memmove(attr.pValue, ctypes.byref(val), ctypes.sizeof(val))
        elif attr.type in data:
            ctypes.memmove(attr.pValue, data[attr.type], len(data[attr.type]))
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attribute_value
    pkcs11_mock.C_Login = lambda *args: 0
    pkcs11_mock.C_Logout = lambda session: 0

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_keys(wallet_id=1, pin=None)

    out = capsys.readouterr().out
    assert "CKA_VALUE (HEX)" in out
    assert "(TEXT)" not in out
    assert "      CKA_LABEL: gost" in out
    assert "      CKA_LABEL (HEX): 67 6F 73 74" in out
    assert "      CKA_ID: id" in out
    assert "      CKA_ID (HEX): 69 64" in out
    assert (
        "      CKA_VALUE (HEX): 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
        in out
    )
    assert (
        " " * 23 + "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F" in out
    )


def test_list_keys_ec_prints_params(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0

    pkcs11_mock.C_OpenSession = open_session

    current_class = None

    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attr = arr[0]
        val_ptr = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong))
        nonlocal current_class
        current_class = val_ptr.contents.value
        return 0

    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        if (
            current_class == structs.CKO_PUBLIC_KEY
            and not hasattr(find_objects, "pub_done")
        ):
            obj_ptr._obj.value = 210
            count_ptr._obj.value = 1
            find_objects.pub_done = True
        else:
            count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0

    attr_map = {
        210: {
            structs.CKA_LABEL: b"ec",
            structs.CKA_ID: b"ec-id",
            structs.CKA_EC_PARAMS: bytes(range(1, 35)),
            structs.CKA_EC_POINT: bytes(range(35, 55)),
            structs.CKA_KEY_TYPE: structs.CKK_EC,
        }
    }

    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        handle = obj if isinstance(obj, int) else obj.value
        data = attr_map.get(handle, {})

        if not attr.pValue:
            if attr.type == structs.CKA_KEY_TYPE:
                attr.ulValueLen = ctypes.sizeof(ctypes.c_ulong)
            elif attr.type in data:
                attr.ulValueLen = len(data[attr.type])
            else:
                attr.ulValueLen = 0
            return 0

        if attr.type == structs.CKA_KEY_TYPE:
            val = ctypes.c_ulong(data.get(attr.type, 0))
            ctypes.memmove(attr.pValue, ctypes.byref(val), ctypes.sizeof(val))
        elif attr.type in data:
            ctypes.memmove(attr.pValue, data[attr.type], len(data[attr.type]))
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attribute_value
    pkcs11_mock.C_Login = lambda *args: 0
    pkcs11_mock.C_Logout = lambda session: 0

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_keys(wallet_id=1, pin=None)

    out = capsys.readouterr().out
    assert "CKA_EC_PARAMS (HEX)" in out
    assert "CKA_EC_POINT (HEX)" in out
    assert "(TEXT)" not in out


def test_list_keys_rsa_prints_modulus(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0

    pkcs11_mock.C_OpenSession = open_session

    current_class = None

    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attr = arr[0]
        val_ptr = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong))
        nonlocal current_class
        current_class = val_ptr.contents.value
        return 0

    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        if (
            current_class == structs.CKO_PUBLIC_KEY
            and not hasattr(find_objects, "pub_done")
        ):
            obj_ptr._obj.value = 220
            count_ptr._obj.value = 1
            find_objects.pub_done = True
        else:
            count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0

    attr_map = {
        220: {
            structs.CKA_LABEL: b"rsa",
            structs.CKA_ID: b"rsa-id",
            structs.CKA_MODULUS: bytes(range(1, 33)),
            structs.CKA_PUBLIC_EXPONENT: b"\x01\x00\x01",
            structs.CKA_MODULUS_BITS: (256).to_bytes(4, sys.byteorder),
            structs.CKA_KEY_TYPE: structs.CKK_RSA,
        }
    }

    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        handle = obj if isinstance(obj, int) else obj.value
        data = attr_map.get(handle, {})

        if not attr.pValue:
            if attr.type == structs.CKA_KEY_TYPE:
                attr.ulValueLen = ctypes.sizeof(ctypes.c_ulong)
            elif attr.type in data:
                attr.ulValueLen = len(data[attr.type])
            else:
                attr.ulValueLen = 0
            return 0

        if attr.type == structs.CKA_KEY_TYPE:
            val = ctypes.c_ulong(data.get(attr.type, 0))
            ctypes.memmove(attr.pValue, ctypes.byref(val), ctypes.sizeof(val))
        elif attr.type in data:
            ctypes.memmove(attr.pValue, data[attr.type], len(data[attr.type]))
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attribute_value
    pkcs11_mock.C_Login = lambda *args: 0
    pkcs11_mock.C_Logout = lambda session: 0

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_keys(wallet_id=1, pin=None)

    out = capsys.readouterr().out
    lines = out.splitlines()
    assert "CKA_MODULUS (HEX)" in out
    assert "CKA_PUBLIC_EXPONENT (HEX): 01 00 01" in out
    assert "CKA_MODULUS_BITS (HEX)" in out
    pub_idx = lines.index("    Открытый ключ")
    pub_block = lines[pub_idx + 1 : pub_idx + 8]
    assert "      CKA_LABEL: rsa" in pub_block
    assert "      CKA_LABEL (HEX): 72 73 61" in pub_block
    assert "      CKA_ID: rsa-id" in pub_block
    assert "      CKA_ID (HEX): 72 73 61 2D 69 64" in pub_block


@pytest.mark.parametrize(
    "key_type, public_attrs, private_attrs, forbidden",
    [
        (
            structs.CKK_GOSTR3410,
            {structs.CKA_VALUE: bytes(range(16))},
            {structs.CKA_VALUE: bytes(range(16))},
            ["CKA_VALUE (HEX)"],
        ),
        (
            structs.CKK_EC,
            {
                structs.CKA_EC_PARAMS: bytes(range(1, 9)),
                structs.CKA_EC_POINT: bytes(range(9, 21)),
            },
            {
                structs.CKA_EC_PARAMS: bytes(range(1, 9)),
                structs.CKA_EC_POINT: bytes(range(9, 21)),
            },
            ["CKA_EC_PARAMS (HEX)", "CKA_EC_POINT (HEX)"],
        ),
        (
            structs.CKK_RSA,
            {
                structs.CKA_MODULUS: bytes(range(1, 17)),
                structs.CKA_PUBLIC_EXPONENT: b"\x01\x00\x01",
                structs.CKA_MODULUS_BITS: (128).to_bytes(4, sys.byteorder),
            },
            {
                structs.CKA_MODULUS: bytes(range(1, 17)),
                structs.CKA_PUBLIC_EXPONENT: b"\x01\x00\x01",
                structs.CKA_MODULUS_BITS: (128).to_bytes(4, sys.byteorder),
            },
            [
                "CKA_MODULUS (HEX)",
                "CKA_PUBLIC_EXPONENT (HEX)",
                "CKA_MODULUS_BITS (HEX)",
            ],
        ),
    ],
)
def test_list_keys_private_does_not_print_public_only_attrs(
    monkeypatch, capsys, key_type, public_attrs, private_attrs, forbidden
):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0

    pkcs11_mock.C_OpenSession = open_session

    current_class = None

    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attr = arr[0]
        val_ptr = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong))
        nonlocal current_class
        current_class = val_ptr.contents.value
        return 0

    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        if (
            current_class == structs.CKO_PUBLIC_KEY
            and not hasattr(find_objects, "pub_done")
        ):
            obj_ptr._obj.value = 700
            count_ptr._obj.value = 1
            find_objects.pub_done = True
        elif (
            current_class == structs.CKO_PRIVATE_KEY
            and not hasattr(find_objects, "priv_done")
        ):
            obj_ptr._obj.value = 701
            count_ptr._obj.value = 1
            find_objects.priv_done = True
        else:
            count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0

    base_public = {
        structs.CKA_LABEL: b"pub",
        structs.CKA_ID: b"key-id",
        structs.CKA_KEY_TYPE: key_type,
    }
    base_private = {
        structs.CKA_LABEL: b"priv",
        structs.CKA_ID: b"key-id",
        structs.CKA_KEY_TYPE: key_type,
    }

    attr_map = {
        700: {**base_public, **public_attrs},
        701: {**base_private, **private_attrs},
    }

    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        handle = obj if isinstance(obj, int) else obj.value
        data = attr_map.get(handle, {})

        if not attr.pValue:
            if attr.type == structs.CKA_KEY_TYPE:
                attr.ulValueLen = ctypes.sizeof(ctypes.c_ulong)
            elif attr.type in data:
                attr.ulValueLen = len(data[attr.type])
            else:
                attr.ulValueLen = 0
            return 0

        if attr.type == structs.CKA_KEY_TYPE:
            val = ctypes.c_ulong(data.get(attr.type, 0))
            ctypes.memmove(attr.pValue, ctypes.byref(val), ctypes.sizeof(val))
        elif attr.type in data:
            ctypes.memmove(attr.pValue, data[attr.type], len(data[attr.type]))
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attribute_value
    pkcs11_mock.C_Login = lambda *args: 0
    pkcs11_mock.C_Logout = lambda session: 0

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_keys(wallet_id=1, pin="0000")

    lines = capsys.readouterr().out.splitlines()
    pub_idx = lines.index("    Открытый ключ")
    priv_idx = lines.index("    \u0417\u0430\u043a\u0440\u044b\u0442\u044b\u0439 \u043a\u043b\u044e\u0447")

    def collect_block(start_index):
        block = []
        for line in lines[start_index + 1 :]:
            if not line.startswith("      "):
                break
            block.append(line)
        return block

    public_block = collect_block(pub_idx)
    private_block = collect_block(priv_idx)

    for marker in forbidden:
        assert any(marker in line for line in public_block)
        assert all(marker not in line for line in private_block)

    assert "      CKA_LABEL: pub" in public_block
    assert "      CKA_LABEL (HEX): 70 75 62" in public_block
    assert "      CKA_ID: key-id" in public_block
    assert "      CKA_ID (HEX): 6B 65 79 2D 69 64" in public_block
    assert "      CKA_LABEL: priv" in private_block
    assert "      CKA_LABEL (HEX): 70 72 69 76" in private_block
    assert "      CKA_ID: key-id" in private_block
    assert "      CKA_ID (HEX): 6B 65 79 2D 69 64" in private_block

def test_public_key_label_from_private(monkeypatch, capsys):
    """Public key should display label taken from the corresponding private key."""
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0

    pkcs11_mock.C_OpenSession = open_session

    current_class = None

    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attr = arr[0]
        val_ptr = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong))
        nonlocal current_class
        current_class = val_ptr.contents.value
        return 0

    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        if current_class == structs.CKO_PUBLIC_KEY and not hasattr(find_objects, "pub_done"):
            obj_ptr._obj.value = 10
            count_ptr._obj.value = 1
            find_objects.pub_done = True
        elif current_class == structs.CKO_PRIVATE_KEY and not hasattr(find_objects, "priv_done"):
            obj_ptr._obj.value = 11
            count_ptr._obj.value = 1
            find_objects.priv_done = True
        else:
            count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0
    logout_called = []
    pkcs11_mock.C_Logout = lambda session: logout_called.append(True) or 0

    LABEL = b"my label"

    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        handle = obj if isinstance(obj, int) else obj.value
        if not attr.pValue:
            if attr.type == structs.CKA_KEY_TYPE:
                attr.ulValueLen = ctypes.sizeof(ctypes.c_ulong)
            elif attr.type == structs.CKA_LABEL and handle == 11:
                attr.ulValueLen = len(LABEL)
            else:
                attr.ulValueLen = 0
            return 0
        if attr.type == structs.CKA_KEY_TYPE:
            val = ctypes.c_ulong(structs.CKK_RSA)
            ctypes.memmove(attr.pValue, ctypes.byref(val), ctypes.sizeof(val))
        elif attr.type == structs.CKA_LABEL and handle == 11:
            ctypes.memmove(attr.pValue, LABEL, len(LABEL))
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attribute_value
    login_args = []
    def login(*args, **kwargs):
        login_args.append(args)
        return 0
    pkcs11_mock.C_Login = login

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_keys(wallet_id=1, pin="0000")

    out = capsys.readouterr().out.splitlines()
    pub_index = out.index("    Открытый ключ")
    assert any("CKA_LABEL" in line for line in out[pub_index:pub_index + 5])
    assert login_args[0][1] == structs.CKU_USER
    assert logout_called == [True]


def test_list_keys_prints_all_pairs_with_same_id(monkeypatch, capsys):
    """Multiple key pairs sharing the same CKA_ID should all be displayed."""

    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0

    pkcs11_mock.C_OpenSession = open_session

    current_class = None

    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attr = arr[0]
        val_ptr = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong))
        nonlocal current_class
        current_class = val_ptr.contents.value
        return 0

    pkcs11_mock.C_FindObjectsInit = find_objects_init

    public_handles = iter([100, 102])
    private_handles = iter([101, 103])

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        try:
            if current_class == structs.CKO_PUBLIC_KEY:
                handle = next(public_handles)
            else:
                handle = next(private_handles)
        except StopIteration:
            count_ptr._obj.value = 0
            return 0

        obj_ptr._obj.value = handle
        count_ptr._obj.value = 1
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0

    attr_map = {
        100: {
            structs.CKA_ID: b"shared",
            structs.CKA_LABEL: b"pair",
            structs.CKA_KEY_TYPE: structs.CKK_RSA,
        },
        101: {
            structs.CKA_ID: b"shared",
            structs.CKA_LABEL: b"pair",
            structs.CKA_KEY_TYPE: structs.CKK_RSA,
        },
        102: {
            structs.CKA_ID: b"shared",
            structs.CKA_LABEL: b"pair",
            structs.CKA_KEY_TYPE: structs.CKK_RSA,
        },
        103: {
            structs.CKA_ID: b"shared",
            structs.CKA_LABEL: b"pair",
            structs.CKA_KEY_TYPE: structs.CKK_RSA,
        },
    }

    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        handle = obj if isinstance(obj, int) else obj.value
        data = attr_map.get(handle, {})

        if not attr.pValue:
            if attr.type == structs.CKA_KEY_TYPE:
                attr.ulValueLen = ctypes.sizeof(ctypes.c_ulong)
            elif attr.type in data:
                attr.ulValueLen = len(data[attr.type])
            else:
                attr.ulValueLen = 0
            return 0

        if attr.type == structs.CKA_KEY_TYPE:
            val = ctypes.c_ulong(data.get(attr.type, 0))
            ctypes.memmove(attr.pValue, ctypes.byref(val), ctypes.sizeof(val))
        elif attr.type in data:
            ctypes.memmove(attr.pValue, data[attr.type], len(data[attr.type]))
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attribute_value

    login_calls = []

    def login(*args):
        login_calls.append(args)
        return 0

    pkcs11_mock.C_Login = login
    pkcs11_mock.C_Logout = lambda session: 0

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_keys(wallet_id=1, pin="0000")

    out = capsys.readouterr().out
    assert out.count("Ключ №") == 2
    assert len(login_calls) == 1


def test_list_keys_warns_when_public_missing(monkeypatch, capsys):
    """A missing public key should not cause attribute errors and prints a warning."""

    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0

    pkcs11_mock.C_OpenSession = open_session

    current_class = None

    def find_objects_init(session_handle, template_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attr = arr[0]
        val_ptr = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong))
        nonlocal current_class
        current_class = val_ptr.contents.value
        return 0

    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        if current_class == structs.CKO_PUBLIC_KEY:
            count_ptr._obj.value = 0
            return 0

        if hasattr(find_objects, "done"):
            count_ptr._obj.value = 0
            return 0

        obj_ptr._obj.value = 555
        count_ptr._obj.value = 1
        find_objects.done = True
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    pkcs11_mock.C_CloseSession = lambda session: 0

    LABEL = b"only-private"
    KEY_ID = b"unpaired"

    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        handle = obj if isinstance(obj, int) else obj.value
        if handle != 555:
            return structs.CKR_OBJECT_HANDLE_INVALID

        if not attr.pValue:
            if attr.type == structs.CKA_LABEL:
                attr.ulValueLen = len(LABEL)
            elif attr.type == structs.CKA_ID:
                attr.ulValueLen = len(KEY_ID)
            elif attr.type == structs.CKA_KEY_TYPE:
                attr.ulValueLen = ctypes.sizeof(ctypes.c_ulong)
            else:
                attr.ulValueLen = 0
            return 0

        if attr.type == structs.CKA_LABEL:
            ctypes.memmove(attr.pValue, LABEL, len(LABEL))
        elif attr.type == structs.CKA_ID:
            ctypes.memmove(attr.pValue, KEY_ID, len(KEY_ID))
        elif attr.type == structs.CKA_KEY_TYPE:
            val = ctypes.c_ulong(structs.CKK_RSA)
            ctypes.memmove(attr.pValue, ctypes.byref(val), ctypes.sizeof(val))
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attribute_value
    pkcs11_mock.C_Login = lambda *args: 0
    pkcs11_mock.C_Logout = lambda session: 0

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.list_keys(wallet_id=1, pin="0000")

    out = capsys.readouterr().out
    assert "предупреждение: отсутствует открытый ключ" in out
    assert "C_GetAttributeValue вернула ошибку" not in out


def test_change_pin_success(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 321
        return 0

    pkcs11_mock.C_OpenSession = open_session

    login_calls = []

    def login(session, user_type, pin_ptr, length):
        session_val = session if isinstance(session, int) else session.value
        user_val = user_type if isinstance(user_type, int) else user_type.value
        if isinstance(pin_ptr, (bytes, bytearray)):
            pin_value = bytes(pin_ptr[:length])
        else:
            pin_value = ctypes.string_at(pin_ptr, length)
        login_calls.append((session_val, user_val, pin_value, length))
        return 0

    pkcs11_mock.C_Login = login

    setpin_calls = []

    def set_pin(session, old_ptr, old_len, new_ptr, new_len):
        session_val = session if isinstance(session, int) else session.value
        if isinstance(old_ptr, (bytes, bytearray)):
            old_value = bytes(old_ptr[:old_len])
        else:
            old_value = ctypes.string_at(old_ptr, old_len)
        if isinstance(new_ptr, (bytes, bytearray)):
            new_value = bytes(new_ptr[:new_len])
        else:
            new_value = ctypes.string_at(new_ptr, new_len)
        setpin_calls.append((session_val, old_value, new_value, old_len, new_len))
        return 0

    pkcs11_mock.C_SetPIN = set_pin

    logout_called = []
    pkcs11_mock.C_Logout = lambda session: logout_called.append(session if isinstance(session, int) else session.value) or 0

    close_called = []
    pkcs11_mock.C_CloseSession = lambda session: close_called.append(session if isinstance(session, int) else session.value) or 0

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.change_pin(wallet_id=2, old_pin="0000", new_pin="1234")

    out = capsys.readouterr().out
    assert "PIN-код успешно изменён." in out
    assert login_calls == [(321, structs.CKU_USER, b"0000", 4)]
    assert setpin_calls == [(321, b"0000", b"1234", 4, 4)]
    assert logout_called == [321]
    assert close_called == [321]


def test_change_pin_missing_new_pin(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 111
        return 0

    pkcs11_mock.C_OpenSession = open_session
    pkcs11_mock.C_Login = lambda *args: (_ for _ in ()).throw(AssertionError("Should not login"))
    pkcs11_mock.C_SetPIN = lambda *args: (_ for _ in ()).throw(AssertionError("Should not set pin"))
    pkcs11_mock.C_Logout = lambda session: (_ for _ in ()).throw(AssertionError("Should not logout"))

    close_called = []
    pkcs11_mock.C_CloseSession = lambda session: close_called.append(session if isinstance(session, int) else session.value) or 0

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.change_pin(wallet_id=0, old_pin="0000", new_pin=None)

    captured = capsys.readouterr()
    assert "Необходимо указать текущий и новый PIN-коды" in captured.err
    assert close_called == [111]


def test_import_keys_creates_object(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 555
        return 0

    pkcs11_mock.C_OpenSession = open_session

    login_calls = []

    def login(session, user_type, pin, pin_len):
        login_calls.append((user_type, pin, pin_len))
        return 0

    pkcs11_mock.C_Login = login

    logout_called = []
    pkcs11_mock.C_Logout = (
        lambda session: logout_called.append(session if isinstance(session, int) else session.value)
        or 0
    )

    close_called = []
    pkcs11_mock.C_CloseSession = (
        lambda session: close_called.append(session if isinstance(session, int) else session.value)
        or 0
    )

    captured = {}

    def create_object(session, template_ptr, count, handle_ptr):
        arr_type = structs.CK_ATTRIBUTE * count
        arr = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attrs = {}
        for attr in arr:
            if attr.type == structs.CKA_CLASS:
                attrs['class'] = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong)).contents.value
            elif attr.type == structs.CKA_KEY_TYPE:
                attrs['key_type'] = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong)).contents.value
            elif attr.type == structs.CKA_TOKEN:
                attrs['token'] = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ubyte)).contents.value
            elif attr.type == structs.CKA_PRIVATE:
                attrs['private'] = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ubyte)).contents.value
            elif attr.type == structs.CKA_DERIVE:
                attrs['derive'] = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ubyte)).contents.value
            elif attr.type == structs.CKA_VALUE:
                attrs['value'] = ctypes.string_at(attr.pValue, attr.ulValueLen)
            elif attr.type == structs.CKA_VENDOR_BIP32_CHAINCODE:
                attrs['chaincode'] = ctypes.string_at(attr.pValue, attr.ulValueLen)
            elif attr.type == structs.CKA_EC_PARAMS:
                attrs['ec_params'] = ctypes.string_at(attr.pValue, attr.ulValueLen)
            elif attr.type == structs.CKA_ID:
                attrs['id'] = ctypes.string_at(attr.pValue, attr.ulValueLen)
            elif attr.type == structs.CKA_LABEL:
                attrs['label'] = ctypes.string_at(attr.pValue, attr.ulValueLen)
        captured['attributes'] = attrs
        handle_ptr._obj.value = 777
        return 0

    pkcs11_mock.C_CreateObject = create_object

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    raw_mnemonic = (
        "  abandon   abandon  abandon   abandon abandon abandon "
        "abandon   abandon abandon abandon abandon about  "
    )
    sanitized = " ".join(raw_mnemonic.strip().split())
    normalized = unicodedata.normalize("NFKD", sanitized)
    seed = hashlib.pbkdf2_hmac(
        'sha512', normalized.encode('utf-8'), b'mnemonic', 2048, dklen=64
    )
    digest = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    expected_master = digest[:32]
    expected_chain = digest[32:]

    commands.import_keys(
        wallet_id=7,
        pin="1234",
        mnemonic=raw_mnemonic,
        cka_id="root",
        cka_label="Master",
    )

    result = capsys.readouterr()
    assert 'Мастер-ключ успешно импортирован.' in result.out
    assert result.err == ''

    attrs = captured['attributes']
    assert attrs['class'] == structs.CKO_PRIVATE_KEY
    assert attrs['key_type'] == structs.CKK_VENDOR_BIP32
    assert attrs['token'] == 1
    assert attrs['private'] == 1
    assert attrs['derive'] == 1
    assert attrs['value'] == expected_master
    assert attrs['chaincode'] == expected_chain
    assert attrs['ec_params'] == SECP256K1_OID_DER
    assert attrs['id'] == b'root'
    assert attrs['label'] == b'Master'

    assert login_calls == [(structs.CKU_USER, b"1234", 4)]
    assert logout_called == [555]
    assert close_called == [555]


def test_import_keys_invalid_word_count(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 42
        return 0

    pkcs11_mock.C_OpenSession = open_session
    pkcs11_mock.C_Login = lambda *args: pytest.fail('C_Login should not be called')
    pkcs11_mock.C_CreateObject = lambda *args: pytest.fail('C_CreateObject should not be called')

    logout_called = []
    pkcs11_mock.C_Logout = lambda session: logout_called.append(True) or 0

    close_called = []
    pkcs11_mock.C_CloseSession = (
        lambda session: close_called.append(session if isinstance(session, int) else session.value)
        or 0
    )

    monkeypatch.setattr(pkcs11, "load_pkcs11_lib", lambda: pkcs11_mock)
    monkeypatch.setattr(pkcs11, "initialize_library", lambda x: None)
    monkeypatch.setattr(pkcs11, "finalize_library", lambda x: None)
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.import_keys(wallet_id=0, pin="0000", mnemonic="one two")

    captured = capsys.readouterr()
    assert 'Мнемоническая фраза должна содержать' in captured.err
    assert captured.out == ''
    assert logout_called == []
    assert close_called == [42]
