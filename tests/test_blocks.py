# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

import pytest
from egghatch.shellcode import Shellcode

"""
$ cat tests/files/plain/sd.bin | egghatch
[+] code block [0x0000 - 0x000c]
[+] code block [0x0039 - 0x0045]
[+] code block [0x000c - 0x0039]
"""


def test_sd():
    with open('files/plain/sd.bin') as sd:
        sc = Shellcode(sd.read())

    assert sc.analyze() == {
        "text": {
            "blocks": {
                0x00: 0x0c,
                0x0c: 0x39,
                0x39: 0x45
            }
        },
        "data": {
            "blocks": None
        }
    }
