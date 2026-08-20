import ctypes
from types import SimpleNamespace
import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import commands
import pkcs11
import pkcs11_structs as structs

def test_public_key_has_label(monkeypatch, capsys):
    pkcs11_mock = SimpleNamespace()
    pkcs11_mock.C_Initialize = lambda _: 0
    pkcs11_mock.C_Finalize = lambda _: 0
    pkcs11_mock.C_CloseSession = lambda session: 0
    pkcs11_mock.C_FindObjectsFinal = lambda session: 0
    def open_session(slot, flags, app, notify, session_ptr):
        session_ptr._obj.value = 1
        return 0
    pkcs11_mock.C_OpenSession = open_session

    current_class = None
    def find_objects_init(session_handle, template_ptr, count):
        arr = ctypes.cast(template_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE * count)).contents
        val_ptr = ctypes.cast(arr[0].pValue, ctypes.POINTER(ctypes.c_ulong))
        nonlocal current_class
        current_class = val_ptr.contents.value
        return 0
    pkcs11_mock.C_FindObjectsInit = find_objects_init
    def find_objects(session, obj_ptr, max_obj, count_ptr):
        if current_class == structs.CKO_PUBLIC_KEY and not hasattr(find_objects, 'pub_done'):
            obj_ptr._obj.value = 50
            count_ptr._obj.value = 1
            find_objects.pub_done = True
        else:
            count_ptr._obj.value = 0
        return 0
    pkcs11_mock.C_FindObjects = find_objects

    LABEL = b'MYLABEL'
    def get_attribute_value(session, obj, attr_ptr, count):
        attr = ctypes.cast(attr_ptr, ctypes.POINTER(structs.CK_ATTRIBUTE)).contents
        if not attr.pValue:
            if attr.type == structs.CKA_LABEL:
                attr.ulValueLen = len(LABEL)
            elif attr.type == structs.CKA_KEY_TYPE:
                attr.ulValueLen = ctypes.sizeof(ctypes.c_ulong)
            else:
                attr.ulValueLen = 0
            return 0
        if attr.type == structs.CKA_LABEL:
            ctypes.memmove(attr.pValue, LABEL, len(LABEL))
        elif attr.type == structs.CKA_KEY_TYPE:
            val = ctypes.c_ulong(structs.CKK_RSA)
            ctypes.memmove(attr.pValue, ctypes.byref(val), ctypes.sizeof(val))
        return 0
    pkcs11_mock.C_GetAttributeValue = get_attribute_value

    monkeypatch.setattr(pkcs11, 'load_pkcs11_lib', lambda: pkcs11_mock)
    monkeypatch.setattr(commands, 'define_pkcs11_functions', lambda x: None)

    commands.list_keys(wallet_id=1, pin=None)
    out = capsys.readouterr().out
    assert 'CKA_LABEL' in out
