# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

import pytest
from egghatch.shellcode import Shellcode


def test_sd():
    with open('files/plain/sd.bin') as plain1:
        sc = Shellcode(plain1.read())

    assert sc.analyze() == {
        'text': {
            'blocks': {
                0x00: 0x0c,
                0x0c: 0x39,
                0x39: 0x45
            }
        },
        'data': {
            'blocks': None
        }
    }
