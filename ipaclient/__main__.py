# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
"""
Command Line Interface for IPA administration.

The CLI functionality is implemented in ipalib/cli.py
"""
from ipalib import api, cli


def main():
    cli.run(api)


if __name__ == '__main__':
    main()
