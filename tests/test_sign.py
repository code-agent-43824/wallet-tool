import ctypes
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import commands
import pkcs11_structs as structs


def setup_sign_mock(
    monkeypatch,
    *,
    key_type,
    digest_result=None,
    signature_result=None,
    key_id=b"\x01",
):
    digest_result = digest_result or (b"\xAA" * 32)
    signature_result = signature_result or b"\x55\x66"

    pkcs11_mock = SimpleNamespace()
    pkcs11_mock.C_Initialize = lambda _: 0
    pkcs11_mock.C_Finalize = lambda _: 0

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0

    pkcs11_mock.C_OpenSession = open_session
    close_calls = []
    pkcs11_mock.C_CloseSession = lambda session: close_calls.append(session) or 0

    login_calls = []

    def login(session, user_type, pin_ptr, pin_len):
        pin_value = ctypes.string_at(pin_ptr, pin_len) if pin_ptr else b""
        login_calls.append((user_type, pin_value))
        return 0

    pkcs11_mock.C_Login = login
    logout_calls = []
    pkcs11_mock.C_Logout = lambda session: logout_calls.append(session) or 0

    current_handles = []
    current_index = 0

    public_handles = [10]
    private_handles = [11]

    def find_objects_init(session_handle, template_ptr, count):
        nonlocal current_handles, current_index
        current_index = 0
        arr_type = structs.CK_ATTRIBUTE * count
        attrs = ctypes.cast(template_ptr, ctypes.POINTER(arr_type)).contents
        attr = attrs[0]
        obj_class = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong)).contents.value
        if obj_class == structs.CKO_PUBLIC_KEY:
            current_handles = public_handles
        elif obj_class == structs.CKO_PRIVATE_KEY:
            current_handles = private_handles
        else:
            current_handles = []
        return 0

    pkcs11_mock.C_FindObjectsInit = find_objects_init

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        nonlocal current_index
        if current_index < len(current_handles):
            obj_ptr._obj.value = current_handles[current_index]
            count_ptr._obj.value = 1
            current_index += 1
        else:
            count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0

    key_ids = {handle: key_id for handle in [*public_handles, *private_handles]}

    def get_attribute_value(session, obj, attr_ptr, attr_count):
        attrs = ctypes.cast(
            attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE * attr_count)
        ).contents
        attr = attrs[0]
        handle = obj.value

        if attr.type == structs.CKA_ID:
            value = key_ids.get(handle)
            if not attr.pValue:
                attr.ulValueLen = len(value) if value is not None else 0
                return 0
            if value is not None:
                buf = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
                ctypes.memmove(attr.pValue, buf, len(value))
            return 0

        if attr.type == structs.CKA_KEY_TYPE:
            encoded = key_type.to_bytes(4, sys.byteorder)
            if not attr.pValue:
                attr.ulValueLen = len(encoded)
                return 0
            buf = (ctypes.c_ubyte * len(encoded)).from_buffer_copy(encoded)
            ctypes.memmove(attr.pValue, buf, len(encoded))
            return 0

        attr.ulValueLen = 0
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attribute_value

    digest_inits = []
    pkcs11_mock.C_DigestInit = (
        lambda session, mechanism_ptr: digest_inits.append(
            ctypes.cast(
                mechanism_ptr, ctypes.POINTER(structs.CK_MECHANISM)
            ).contents.mechanism
        )
        or 0
    )

    digest_inputs = []
    digest_buffer = (ctypes.c_ubyte * len(digest_result)).from_buffer_copy(digest_result)

    def digest(session, data_ptr, data_len, digest_ptr, digest_len_ptr):
        if data_ptr:
            digest_inputs.append(ctypes.string_at(data_ptr, data_len))
        else:
            digest_inputs.append(b"")
        if not digest_ptr:
            digest_len_ptr._obj.value = len(digest_result)
        else:
            ctypes.memmove(digest_ptr, digest_buffer, len(digest_result))
            digest_len_ptr._obj.value = len(digest_result)
        return 0

    pkcs11_mock.C_Digest = digest

    sign_mechanisms = []
    signature_calls = []
    signature_buffer = (ctypes.c_ubyte * len(signature_result)).from_buffer_copy(
        signature_result
    )

    def sign_init(session, mechanism_ptr, key_handle):
        mechanism = ctypes.cast(
            mechanism_ptr, ctypes.POINTER(structs.CK_MECHANISM)
        ).contents
        sign_mechanisms.append(mechanism.mechanism)
        return 0

    pkcs11_mock.C_SignInit = sign_init

    def sign(session, data_ptr, data_len, signature_ptr, signature_len_ptr):
        if not signature_ptr:
            signature_len_ptr._obj.value = len(signature_result)
        else:
            signature_calls.append(ctypes.string_at(data_ptr, data_len))
            ctypes.memmove(signature_ptr, signature_buffer, len(signature_result))
            signature_len_ptr._obj.value = len(signature_result)
        return 0

    pkcs11_mock.C_Sign = sign

    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    captures = {
        "login_calls": login_calls,
        "logout_calls": logout_calls,
        "close_calls": close_calls,
        "digest_inits": digest_inits,
        "digest_inputs": digest_inputs,
        "sign_mechanisms": sign_mechanisms,
        "signature_calls": signature_calls,
    }

    return pkcs11_mock, captures


def test_sign_requires_key_number(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()
    pkcs11_mock.C_Initialize = lambda _: 0
    pkcs11_mock.C_Finalize = lambda _: 0
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.run_command_sign(pkcs11_mock, wallet_id=1, pin="0000")

    err = capsys.readouterr().err
    assert "--key-number" in err


def test_sign_requires_pin(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()
    pkcs11_mock.C_Initialize = lambda _: 0
    pkcs11_mock.C_Finalize = lambda _: 0
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)

    commands.run_command_sign(pkcs11_mock, wallet_id=1, pin=None, key_number=1)

    err = capsys.readouterr().err
    assert "PIN-код" in err


def test_sign_hash_invalid_format(monkeypatch, capsys):
    pkcs11_mock, _ = setup_sign_mock(monkeypatch, key_type=structs.CKK_EC)

    commands.run_command_sign(
        pkcs11_mock,
        wallet_id=1,
        pin="0000",
        key_number=1,
        hash_value="ZZ",
    )

    err = capsys.readouterr().err
    assert "Некорректное значение параметра --hash" in err


def test_sign_hash_ec_success(monkeypatch, capsys):
    pkcs11_mock, captured = setup_sign_mock(
        monkeypatch,
        key_type=structs.CKK_EC,
        signature_result=b"\x01\x02",
    )

    hash_value = "AA" * 32
    commands.run_command_sign(
        pkcs11_mock,
        wallet_id=1,
        pin="0000",
        key_number=1,
        hash_value=hash_value,
    )

    out = capsys.readouterr().out
    assert "Подпись (HEX):" in out
    assert captured["sign_mechanisms"] == [structs.CKM_ECDSA]
    assert captured["signature_calls"] == [bytes.fromhex(hash_value)]


def test_sign_data_ec_uses_digest(monkeypatch):
    digest_value = b"\x11" * 32
    pkcs11_mock, captured = setup_sign_mock(
        monkeypatch,
        key_type=structs.CKK_EC,
        digest_result=digest_value,
    )

    commands.run_command_sign(
        pkcs11_mock,
        wallet_id=1,
        pin="0000",
        key_number=1,
        data="hello",
    )

    assert captured["digest_inits"] == [structs.CKM_SHA256]
    assert captured["digest_inputs"][0] == b"hello"
    assert captured["signature_calls"] == [digest_value]


def test_sign_hash_rsa_wraps_digest(monkeypatch):
    pkcs11_mock, captured = setup_sign_mock(
        monkeypatch,
        key_type=structs.CKK_RSA,
        signature_result=b"\x01",
    )

    digest_hex = "11" * 32
    commands.run_command_sign(
        pkcs11_mock,
        wallet_id=1,
        pin="0000",
        key_number=1,
        hash_value=digest_hex,
    )

    expected_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    assert captured["sign_mechanisms"] == [structs.CKM_RSA_PKCS]
    assert captured["signature_calls"] == [expected_prefix + bytes.fromhex(digest_hex)]
