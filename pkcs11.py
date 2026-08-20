import os
import sys
import ctypes


def load_pkcs11_lib():
    # выбрать имя файла библиотеки для текущей платформы
    if sys.platform.startswith("win"):
        lib_filename = "wtpkcs11ecp.dll"
        loader = ctypes.WinDLL
    elif sys.platform == "darwin":
        lib_filename = "wtpkcs11ecp.dylib"
        loader = ctypes.CDLL
    else:
        lib_filename = "libwtpkcs11ecp.so"
        loader = ctypes.CDLL

    # путь к директории самого исполняемого файла (dist/)
    runtime_dir = os.path.dirname(sys.executable)
    lib_path = os.path.join(runtime_dir, lib_filename)

    try:
        return loader(lib_path)
    except OSError as e:
        raise RuntimeError(f"Ошибка загрузки {lib_path}: {e}") from e


def pkcs11_command(func):
    """Загрузить библиотеку и передать её первым аргументом команде.

    Тело каждой команды живёт в отдельной функции run_command_*, которая
    принимает библиотеку параметром: так её можно вызвать в тестах с мок-объектом
    вместо настоящей библиотеки.
    """

    def wrapper(*args, **kwargs):
        pkcs11 = load_pkcs11_lib()
        return func(pkcs11, *args, **kwargs)

    return wrapper
