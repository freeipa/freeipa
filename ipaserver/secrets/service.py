# Copyright (C) 2017  IPA Project Contributors, see COPYING for license
import argparse

import ipaserver.custodia.server  # pylint: disable=relative-import


argparser = argparse.ArgumentParser(
    prog='ipa-custodia',
    description='IPA Custodia service'
)
argparser.add_argument(
    '--debug',
    action='store_true',
    help='Debug mode'
)
argparser.add_argument(
    'configfile',
    nargs='?',
    type=argparse.FileType('r'),
    help="Path to IPA's custodia server config",
    default='/etc/ipa/custodia/custodia.conf'
)


def main():
    return ipaserver.custodia.server.main(argparser)


if __name__ == '__main__':
    main()
