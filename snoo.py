import re
import sys
import os
import argparse

from parser import SnoopParser
from parser import SnoopConfig
from pprint import pprint


def handle_args():
    parser = argparse.ArgumentParser(
        prog='snoo.py',
        description='Parse a pdweb.snoop trace')
    parser.add_argument('-t', '--text_only', default=False,
                        action='store_true', help="don't print data as hex")
    parser.add_argument('-n', '--no_data', default=False,
                        action='store_true', help="don't print data")
    parser.add_argument('-i', '--id', action='append',
                        help="filter for thread id, can be specified multiple times", type=int)
    parser.add_argument('file', help="FILE")
    args = parser.parse_args()
    return SnoopConfig(args.file, args.text_only, args.no_data, args.id)


def main() -> int:
    try:
        config = handle_args()
        parser = SnoopParser(config)
        for entry in parser:
            print(entry)
    # handle the error output when piping
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    return 0


if __name__ == '__main__':
    sys.exit(main())
