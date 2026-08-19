import ctypes
import importlib.util
import os
import sys
import warnings

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pkcs11_structs as structs

MODULE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "pkcs11_structs.py")
)

# Структуры, которым _pack_ выставляется на любой платформе.
ALWAYS_PACKED = (
    structs.CK_ATTRIBUTE,
    structs.CK_MECHANISM,
    structs.CK_VENDOR_BIP32_WITH_BIP39_KEY_PAIR_GEN_PARAMS,
)


def iter_structures(module):
    for name in dir(module):
        obj = getattr(module, name)
        if isinstance(obj, type) and issubclass(obj, ctypes.Structure):
            yield name, obj


def load_fresh_copy():
    """Импортировать pkcs11_structs отдельной копией, не трогая sys.modules."""

    spec = importlib.util.spec_from_file_location(
        "_pkcs11_structs_layout_check", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pack_always_comes_with_explicit_layout():
    """_pack_ без _layout_ — ошибка импорта начиная с Python 3.19."""

    checked = 0
    for name, cls in iter_structures(structs):
        if "_pack_" not in vars(cls):
            continue
        checked += 1
        assert vars(cls).get("_layout_") == "ms", (
            f"{name} объявляет _pack_, но не _layout_"
        )
    assert checked, "не найдено ни одной структуры с _pack_"


def test_packed_structures_have_no_padding():
    """_layout_ = 'ms' должен сохранять ту же раскладку, что даёт _pack_ = 1."""

    for cls in ALWAYS_PACKED:
        expected_offset = 0
        for field_name, *_ in cls._fields_:
            field = getattr(cls, field_name)
            assert field.offset == expected_offset, (
                f"{cls.__name__}.{field_name}: смещение {field.offset}, "
                f"ожидалось {expected_offset}"
            )
            expected_offset += field.size
        assert ctypes.sizeof(cls) == expected_offset


def test_import_emits_no_deprecation_warning():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        load_fresh_copy()

    deprecations = [
        str(item.message)
        for item in caught
        if issubclass(item.category, DeprecationWarning)
    ]
    assert deprecations == []
