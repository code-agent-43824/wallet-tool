import ctypes
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import commands
import pkcs11_structs as structs


def make_library_mock(monkeypatch, *, initialize_rv=0, get_info_rv=0):
    """Мок для команд, которым сессия не нужна."""

    pkcs11_mock = SimpleNamespace()
    pkcs11_mock.C_Initialize = lambda _: initialize_rv
    pkcs11_mock.C_Finalize = lambda _: 0

    def get_info(info_ptr):
        return get_info_rv

    pkcs11_mock.C_GetInfo = get_info
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)
    return pkcs11_mock


def make_session_mock(monkeypatch, *, open_session_rv=0):
    """Мок с сессией без единого объекта на токене."""

    pkcs11_mock = SimpleNamespace()
    pkcs11_mock.C_Initialize = lambda _: 0
    pkcs11_mock.C_Finalize = lambda _: 0

    def open_session(slot, flags, app, notify, session_ptr):
        if open_session_rv == 0:
            session_ptr._obj.value = 7
        return open_session_rv

    pkcs11_mock.C_OpenSession = open_session
    pkcs11_mock.C_CloseSession = lambda session: 0
    pkcs11_mock.C_Login = lambda *args: 0
    pkcs11_mock.C_Logout = lambda session: 0
    pkcs11_mock.C_FindObjectsInit = lambda *args: 0
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0

    def find_objects(session, obj_ptr, max_obj, count_ptr):
        count_ptr._obj.value = 0
        return 0

    pkcs11_mock.C_FindObjects = find_objects
    monkeypatch.setattr(commands, "define_pkcs11_functions", lambda x: None)
    return pkcs11_mock


def test_library_info_returns_ok(monkeypatch):
    pkcs11_mock = make_library_mock(monkeypatch)

    assert commands.run_command_library_info(pkcs11_mock) == commands.EXIT_OK


def test_library_info_reports_failed_initialize(monkeypatch, capsys):
    pkcs11_mock = make_library_mock(monkeypatch, initialize_rv=5)

    assert commands.run_command_library_info(pkcs11_mock) == commands.EXIT_ERROR
    assert 'C_Initialize' in capsys.readouterr().out


def test_library_info_reports_failed_get_info(monkeypatch, capsys):
    pkcs11_mock = make_library_mock(monkeypatch, get_info_rv=3)

    assert commands.run_command_library_info(pkcs11_mock) == commands.EXIT_ERROR
    assert 'C_GetInfo' in capsys.readouterr().out


def test_list_keys_reports_missing_wallet(monkeypatch, capsys):
    pkcs11_mock = make_session_mock(
        monkeypatch, open_session_rv=structs.CKR_TOKEN_NOT_PRESENT
    )

    assert (
        commands.run_command_list_keys(pkcs11_mock, wallet_id=0, pin='0000')
        == commands.EXIT_ERROR
    )
    assert 'Нет подключенного кошелька' in capsys.readouterr().out


def test_list_keys_returns_ok_on_empty_token(monkeypatch):
    pkcs11_mock = make_session_mock(monkeypatch)

    assert (
        commands.run_command_list_keys(pkcs11_mock, wallet_id=0, pin='0000')
        == commands.EXIT_OK
    )


def test_sign_without_key_number_reports_error(monkeypatch, capsys):
    pkcs11_mock = make_session_mock(monkeypatch)

    assert (
        commands.run_command_sign(pkcs11_mock, wallet_id=0, pin='0000', data='x')
        == commands.EXIT_ERROR
    )
    assert '--key-number' in capsys.readouterr().err


def test_sign_reports_unknown_key_number(monkeypatch, capsys):
    pkcs11_mock = make_session_mock(monkeypatch)

    assert (
        commands.run_command_sign(
            pkcs11_mock, wallet_id=0, pin='0000', key_number=1, data='x'
        )
        == commands.EXIT_ERROR
    )
    assert 'Ключ с таким номером не найден' in capsys.readouterr().err


def test_delete_without_key_number_reports_error(monkeypatch, capsys):
    pkcs11_mock = make_session_mock(monkeypatch)

    assert (
        commands.run_command_delete_key_pair(pkcs11_mock, wallet_id=0, pin='0000')
        == commands.EXIT_ERROR
    )
    assert '--key-number' in capsys.readouterr().err


def test_delete_force_returns_ok_on_empty_token(monkeypatch):
    pkcs11_mock = make_session_mock(monkeypatch)
    pkcs11_mock.C_DestroyObject = lambda session, handle: 0

    assert (
        commands.run_command_delete_key_pair(
            pkcs11_mock, wallet_id=0, pin='0000', force=True
        )
        == commands.EXIT_OK
    )


def test_import_without_mnemonic_reports_error(monkeypatch, capsys):
    pkcs11_mock = make_session_mock(monkeypatch)

    assert (
        commands.run_command_import_keys(pkcs11_mock, wallet_id=0, pin='0000')
        == commands.EXIT_ERROR
    )
    assert 'мнемоническую фразу' in capsys.readouterr().err


def test_generate_with_unknown_algorithm_reports_error(monkeypatch, capsys):
    pkcs11_mock = make_session_mock(monkeypatch)

    assert (
        commands.run_command_generate_key_pair(
            pkcs11_mock,
            wallet_id=0,
            pin='0000',
            algorithm='нет такого',
            cka_id='id',
            cka_label='label',
        )
        == commands.EXIT_ERROR
    )
    assert 'Неверный тип ключа' in capsys.readouterr().out


def test_change_pin_without_new_pin_reports_error(monkeypatch, capsys):
    pkcs11_mock = make_session_mock(monkeypatch)
    pkcs11_mock.C_SetPIN = lambda *args: 0

    assert (
        commands.run_command_change_pin(pkcs11_mock, wallet_id=0, old_pin='0000')
        == commands.EXIT_ERROR
    )
    assert 'текущий и новый PIN-коды' in capsys.readouterr().err
