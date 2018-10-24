#!/usr/bin/python3
"""Helper script to test LGTM config

$ contrib/lgtm_container.py > Dockerfile
$ docker build -t lgtm .
"""
import os
import yaml

LGTM_YML = os.path.join(os.path.dirname(__file__), '..', '.lgtm.yml')


def main():
    with open(LGTM_YML) as f:
        cfg = yaml.safe_load(f)

    python = cfg['extraction']['python']

    print("""\
    FROM ubuntu:bionic
    RUN apt-get update && \
        apt-get install -y {dpkg} python3-venv && \
        apt-get clean
    RUN python3 -m venv /venv
    RUN /venv/bin/pip install wheel
    RUN /venv/bin/pip install {pypkg}
    ADD . /freeipa
    RUN cd /freeipa && ./autogen.sh --with-ipaplatform=debian
    """.format(
        dpkg=' '.join(python['prepare']['packages']),
        pypkg=' '.join(python['python_setup']['requirements'])
    ))


if __name__ == '__main__':
    main()
