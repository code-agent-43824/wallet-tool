import ctypes
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import commands
import pkcs11
import pkcs11_structs as structs

# OID кривой secp256k1 (1.3.132.0.10) в DER — сверяем литералом, а не константой
# из commands.py, иначе проверка пройдёт при любом её значении.
SECP256K1_OID_DER = bytes((0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A))


def make_pkcs11_mock(captured):
    pkcs11_mock = SimpleNamespace()
    pkcs11_mock.C_Initialize = lambda _: 0
    pkcs11_mock.C_Finalize = lambda _: 0

    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0
    pkcs11_mock.C_OpenSession = open_session
    captured['login_args'] = []
    captured['logout_called'] = 0
    def login(*args, **kwargs):
        captured['login_args'].append(args)
        return 0
    pkcs11_mock.C_Login = login
    def logout(session):
        captured['logout_called'] += 1
        return 0
    pkcs11_mock.C_Logout = logout
    pkcs11_mock.C_CloseSession = lambda session: 0

    captured['mnemonic_size_requests'] = []
    captured['mnemonic_value_requests'] = 0
    captured['mnemonic_locked_value'] = None

    sample_mnemonic = (
        'abandon ability able about above absent absorb abstract absurd abuse access '
        'accident account accuse achieve acid acoustic acquire across act action '
        'actor actress actual'
    ).encode('utf-8')
    captured['sample_mnemonic'] = sample_mnemonic

    def generate_key_pair(session, mech_ptr, pub_tpl, pub_count, priv_tpl, priv_count, pub_h_ptr, priv_h_ptr):
        mech = ctypes.cast(mech_ptr, ctypes.POINTER(structs.CK_MECHANISM)).contents
        captured['mechanism'] = mech.mechanism
        captured['mechanism_parameter'] = mech.pParameter
        if mech.pParameter:
            params = ctypes.cast(
                mech.pParameter,
                ctypes.POINTER(structs.CK_VENDOR_BIP32_WITH_BIP39_KEY_PAIR_GEN_PARAMS),
            ).contents
            captured['mechanism_passphrase_len'] = params.ulPassphraseLen
            captured['mechanism_mnemonic_len'] = params.ulMnemonicLength
            captured['mechanism_passphrase_ptr'] = params.pPassphrase

        def read_attrs(ptr, count, prefix):
            arr_type = structs.CK_ATTRIBUTE * count
            arr = ctypes.cast(ptr, ctypes.POINTER(arr_type)).contents
            for attr in arr:
                if attr.type == structs.CKA_MODULUS_BITS:
                    val = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong)).contents.value
                    captured['modulus_bits'] = val
                elif attr.type in (
                    structs.CKA_TOKEN,
                    structs.CKA_PRIVATE,
                    structs.CKA_VENDOR_BIP39_MNEMONIC_IS_EXTRACTABLE,
                ):
                    val = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ubyte)).contents.value
                    captured[f'{prefix}_{attr.type}'] = val
                elif attr.type == structs.CKA_KEY_TYPE:
                    val = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ulong)).contents.value
                    captured[f'{prefix}_{attr.type}'] = val
                elif attr.type in (
                    structs.CKA_ID,
                    structs.CKA_LABEL,
                    structs.CKA_GOSTR3410_PARAMS,
                    structs.CKA_GOSTR3411_PARAMS,
                    structs.CKA_EC_PARAMS,
                ):
                    buf = (ctypes.c_ubyte * attr.ulValueLen).from_address(attr.pValue)
                    captured[f'{prefix}_{attr.type}'] = bytes(buf)

        read_attrs(pub_tpl, pub_count, 'pub')
        read_attrs(priv_tpl, priv_count, 'priv')
        return 0
    pkcs11_mock.C_GenerateKeyPair = generate_key_pair

    def get_attribute_value(session, obj, attrs_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        attrs = ctypes.cast(attrs_ptr, ctypes.POINTER(arr_type)).contents
        for attr in attrs:
            if attr.type == structs.CKA_VENDOR_BIP39_MNEMONIC:
                if not attr.pValue:
                    attr.ulValueLen = len(sample_mnemonic)
                    captured['mnemonic_size_requests'].append(attr.ulValueLen)
                else:
                    ctypes.memmove(attr.pValue, sample_mnemonic, len(sample_mnemonic))
                    captured['mnemonic_value_requests'] += 1
        return 0

    pkcs11_mock.C_GetAttributeValue = get_attribute_value

    def set_attribute_value(session, obj, attrs_ptr, count):
        arr_type = structs.CK_ATTRIBUTE * count
        attrs = ctypes.cast(attrs_ptr, ctypes.POINTER(arr_type)).contents
        for attr in attrs:
            if attr.type == structs.CKA_VENDOR_BIP39_MNEMONIC_IS_EXTRACTABLE:
                val = ctypes.cast(attr.pValue, ctypes.POINTER(ctypes.c_ubyte)).contents.value
                captured['mnemonic_locked_value'] = val
        return 0

    pkcs11_mock.C_SetAttributeValue = set_attribute_value

    return pkcs11_mock


def setup(monkeypatch, captured):
    pkcs11_mock = make_pkcs11_mock(captured)
    monkeypatch.setattr(pkcs11, 'load_pkcs11_lib', lambda: pkcs11_mock)
    monkeypatch.setattr(commands, 'define_pkcs11_functions', lambda x: None)


def test_generate_rsa2048(monkeypatch):
    captured = {}
    setup(monkeypatch, captured)

    commands.generate_key_pair(
        wallet_id=1,
        pin='1111',
        algorithm='rsa2048',
        cka_id='01',
        cka_label='lbl',
    )

    assert captured['mechanism'] == structs.CKM_RSA_PKCS_KEY_PAIR_GEN
    assert captured['modulus_bits'] == 2048
    assert captured['pub_%d' % structs.CKA_TOKEN] == 1
    assert captured['priv_%d' % structs.CKA_PRIVATE] == 1
    assert captured['pub_%d' % structs.CKA_PRIVATE] == 0
    assert captured['pub_%d' % structs.CKA_ID] == b'01'
    assert captured['priv_%d' % structs.CKA_ID] == b'01'
    assert captured['pub_%d' % structs.CKA_LABEL] == b'lbl'
    assert captured['login_args'][0][1] == structs.CKU_USER
    assert captured['priv_%d' % structs.CKA_LABEL] == b'lbl'
    assert captured['logout_called'] == 1


def test_generate_ed25519(monkeypatch):
    captured = {}
    setup(monkeypatch, captured)

    commands.generate_key_pair(
        wallet_id=1,
        pin='1111',
        algorithm='ed25519',
        cka_id='AA',
        cka_label='x',
    )

    assert captured['mechanism'] == structs.CKM_EC_EDWARDS_KEY_PAIR_GEN
    assert captured['pub_%d' % structs.CKA_ID] == b'AA'
    assert captured['priv_%d' % structs.CKA_LABEL] == b'x'
    assert captured['login_args'][0][1] == structs.CKU_USER
    assert captured['logout_called'] == 1


def test_generate_secp256_default(monkeypatch):
    captured = {}
    setup(monkeypatch, captured)

    commands.generate_key_pair(
        wallet_id=1,
        pin='1111',
        algorithm='secp256',
        cka_id='12',
        cka_label='secp',
    )

    assert captured['mechanism'] == structs.CKM_EC_KEY_PAIR_GEN
    assert not captured['mechanism_parameter']
    assert 'priv_%d' % structs.CKA_VENDOR_BIP39_MNEMONIC_IS_EXTRACTABLE not in captured
    assert captured['pub_%d' % structs.CKA_KEY_TYPE] == structs.CKK_EC
    assert captured['priv_%d' % structs.CKA_KEY_TYPE] == structs.CKK_EC
    assert captured['pub_%d' % structs.CKA_EC_PARAMS] == SECP256K1_OID_DER
    assert captured['logout_called'] == 1


def test_generate_secp256_with_mnemonic(monkeypatch, capsys):
    captured = {}
    setup(monkeypatch, captured)

    commands.generate_key_pair(
        wallet_id=1,
        pin='1111',
        algorithm='secp256',
        cka_id='12',
        cka_label='secp',
        get_mnemonic=True,
    )

    out = capsys.readouterr().out

    assert captured['mechanism'] == structs.CKM_VENDOR_BIP32_WITH_BIP39_KEY_PAIR_GEN
    assert captured['mechanism_passphrase_len'] == 0
    assert captured['mechanism_mnemonic_len'] == 24
    assert captured['mechanism_passphrase_ptr'] != 0
    assert (
        'priv_%d' % structs.CKA_VENDOR_BIP39_MNEMONIC_IS_EXTRACTABLE not in captured
    )
    assert captured['pub_%d' % structs.CKA_KEY_TYPE] == structs.CKK_VENDOR_BIP32
    assert captured['priv_%d' % structs.CKA_KEY_TYPE] == structs.CKK_VENDOR_BIP32
    assert captured['pub_%d' % structs.CKA_EC_PARAMS] == SECP256K1_OID_DER
    assert captured['mnemonic_size_requests'] == [len(captured['sample_mnemonic'])]
    assert captured['mnemonic_value_requests'] == 1
    assert captured['mnemonic_locked_value'] == 0
    assert 'ЗАПИШИТЕ МНЕМОНИЧЕСКУЮ ФРАЗУ' in out
    assert captured['sample_mnemonic'].decode('utf-8') in out
    assert captured['logout_called'] == 1


def test_generate_mnemonic_wrong_algorithm(monkeypatch, capsys):
    captured = {}
    setup(monkeypatch, captured)

    commands.generate_key_pair(
        wallet_id=1,
        pin='1111',
        algorithm='ed25519',
        cka_id='AA',
        cka_label='x',
        get_mnemonic=True,
    )

    err = capsys.readouterr().err
    assert '--get-mnemonic' in err
    assert captured['login_args'] == []
    assert captured['logout_called'] == 0


def test_generate_missing_id_label(monkeypatch, capsys):
    captured = {}
    setup(monkeypatch, captured)

    commands.generate_key_pair(
        wallet_id=1,
        pin='1111',
        algorithm='ed25519',
        cka_id='',
        cka_label='',
    )

    err = capsys.readouterr().err
    assert 'key-id' in err and 'key-label' in err
    assert captured['login_args'] == []
    assert captured['logout_called'] == 0


def test_generate_gost_params(monkeypatch):
    captured = {}
    setup(monkeypatch, captured)

    commands.generate_key_pair(
        wallet_id=1,
        pin='1111',
        algorithm='gost',
        cka_id='GG',
        cka_label='lbl',
    )

    assert captured['mechanism'] == structs.CKM_GOSTR3410_KEY_PAIR_GEN
    assert 'pub_%d' % structs.CKA_GOSTR3410_PARAMS in captured
    assert 'pub_%d' % structs.CKA_GOSTR3411_PARAMS in captured
    assert 'priv_%d' % structs.CKA_GOSTR3410_PARAMS in captured
    assert 'priv_%d' % structs.CKA_GOSTR3411_PARAMS in captured
    assert captured['login_args'][0][1] == structs.CKU_USER
    assert captured['logout_called'] == 1


