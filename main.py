import argparse
import getpass
import sys
from commands import (
    library_info,
    list_slots,
    list_wallets,
    list_keys,
    generate_key_pair,
    delete_key_pair,
    change_pin,
    show_wallet_info,
    import_keys,
    sign,
)

# Для Windows: переключаем потоки в UTF-8, чтобы не падать на кириллице
if sys.platform.startswith("win") and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


class CustomArgumentParser(argparse.ArgumentParser):
    def format_help(self):
        base_help = super().format_help()
        return "Инструмент для работы с wtpkcs11ecp\n" + base_help


# Маркер: параметр указан без значения, секрет нужно запросить.
PROMPT = object()


def read_secret(prompt):
    """Прочитать секрет, не оставляя его в истории оболочки.

    С терминала читаем через ``getpass``, чтобы ввод не отображался. Если stdin
    перенаправлен (конвейер, файл), берём одну строку — так утилита остаётся
    пригодной для скриптов.
    """

    if sys.stdin is not None and sys.stdin.isatty():
        return getpass.getpass(prompt)

    line = sys.stdin.readline()
    if not line:
        return ''
    return line.rstrip('\n').rstrip('\r')


def resolve_secret(value, prompt, required):
    """Определить секрет: из аргумента, запросом или оставить пустым.

    ``value`` — то, что положил argparse: строка, ``PROMPT`` (параметр указан без
    значения) или ``None`` (параметр не указан). Когда секрет обязателен, его
    запрашивают и в последнем случае.
    """

    if value is PROMPT:
        return read_secret(prompt)
    if value is not None:
        return value
    if required:
        return read_secret(prompt)
    return None


def main():
    parser = CustomArgumentParser(
        description='Утилита для работы с PKCS#11 библиотекой Рутокен',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
    )
    parser.add_argument(
        '-h',
        '--help',
        action='help',
        default=argparse.SUPPRESS,
        help='Показать это справочное сообщение и завершить работу',
    )
    parser.add_argument('--library-info', action='store_true',
                        help='Показать информацию о библиотеке (C_GetInfo)')
    parser.add_argument('--list-slots', action='store_true',
                        help='Показать список доступных слотов')
    parser.add_argument('--list-wallets', action='store_true',
                        help='Показать список кошельков (токенов)')
    parser.add_argument('--show-wallet-info', action='store_true',
                        help='Показать подробную информацию о кошельке')
    parser.add_argument('--list-keys', action='store_true',
                        help='Показать список ключей в кошельке')
    parser.add_argument(
        '--import-key',
        type=str,
        help='Импортировать master node из мнемонической фразы',
    )
    parser.add_argument('--generate-key', choices=['secp256', 'ed25519', 'gost', 'rsa1024', 'rsa2048'],
                        help='Сгенерировать ключевую пару указанного типа')
    parser.add_argument('--key-id', type=str, default='',
                        help='CKA_ID для создаваемой ключевой пары')
    parser.add_argument('--key-label', type=str, default='',
                        help='CKA_LABEL для создаваемой ключевой пары')
    parser.add_argument(
        '--get-mnemonic',
        action='store_true',
        help='Получить мнемоническую фразу при генерации secp256 ключа',
    )
    parser.add_argument(
        '--delete-key',
        action='store_true',
        help='Удалить ключевую пару; требуется параметр --key-number или --force',
    )
    parser.add_argument(
        '--key-number',
        type=int,
        help='Номер ключа из списка (key-number) для удаления',
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Удалить все объекты на токене (требуется PIN, несовместимо с --key-number)',
    )
    parser.add_argument('--change-pin', action='store_true',
                        help='Сменить пользовательский PIN-код')
    parser.add_argument('--sign', action='store_true',
                        help='Подписать данные выбранным ключом')
    parser.add_argument('--new-pin', nargs='?', const=PROMPT, default=None,
                        help='Новый PIN-код для смены; без значения будет запрошен')
    parser.add_argument('--wallet-id', type=int, default=0,
                        help='Идентификатор кошелька для выполнения команды (по умолчанию 0)')
    parser.add_argument('--pin', nargs='?', const=PROMPT, default=None,
                        help='PIN-код для выполнения команды.\n'
                             'Без значения или без самого параметра PIN будет запрошен,\n'
                             'чтобы не оставлять его в истории оболочки и списке процессов.\n'
                             'Для --list-keys без параметра показываются только открытые ключи')
    parser.add_argument('--hash', dest='hash_value', type=str, default=None,
                        help='Готовый хэш для подписи (HEX-строка)')
    parser.add_argument('--data', type=str, default=None,
                        help='Произвольные данные для подписи (перед подписью будут хэшированы)')

    args = parser.parse_args()

    if args.library_info:
        library_info()
    elif args.list_slots:
        list_slots()
    elif args.list_wallets:
        list_wallets()
    elif args.show_wallet_info:
        show_wallet_info(args.wallet_id)
    elif args.list_keys:
        # PIN здесь не обязателен: без него показываются только открытые ключи.
        list_keys(args.wallet_id, resolve_secret(args.pin, 'PIN-код: ', False))
    elif args.import_key is not None:
        import_keys(
            args.wallet_id,
            resolve_secret(args.pin, 'PIN-код: ', True),
            args.import_key,
            cka_id=args.key_id,
            cka_label=args.key_label,
        )
    elif args.generate_key:
        if not args.key_id or not args.key_label:
            print('Необходимо указать --key-id и --key-label для генерации ключа', file=sys.stderr)
        else:
            generate_key_pair(
                args.wallet_id,
                resolve_secret(args.pin, 'PIN-код: ', True),
                args.generate_key,
                cka_id=args.key_id,
                cka_label=args.key_label,
                get_mnemonic=args.get_mnemonic,
            )
    elif args.delete_key:
        if args.force and args.key_number is not None:
            print('Нельзя использовать одновременно параметры --force и --key-number', file=sys.stderr)
        elif not args.force and args.key_number is None:
            print('Для удаления необходимо указать параметр --key-number', file=sys.stderr)
        else:
            delete_key_pair(
                args.wallet_id,
                resolve_secret(args.pin, 'PIN-код: ', True),
                key_number=args.key_number,
                force=args.force,
            )
    elif args.change_pin:
        change_pin(
            args.wallet_id,
            resolve_secret(args.pin, 'Текущий PIN-код: ', True),
            resolve_secret(args.new_pin, 'Новый PIN-код: ', True),
        )
    elif args.sign:
        sign(
            args.wallet_id,
            resolve_secret(args.pin, 'PIN-код: ', True),
            key_number=args.key_number,
            hash_value=args.hash_value,
            data=args.data,
        )
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
