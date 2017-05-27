# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

from egghatch.shellcode import Shellcode

def test_sd():
    # http://shell-storm.org/shellcode/files/shellcode-554.php
    sc = Shellcode(open("tests/files/plain/sd.bin", "rb").read())

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

def test_bin1():
    sc = Shellcode(open("tests/files/plain/1.bin", "rb").read())
    assert sc.analyze() == {
        "text": {
            "blocks": {
                0x00: 0x06,
                0x88: 0xb9,
                0xc0: 0x105,
                0x105: 0x108,
                0x108: 0x10f,
                0x10f: 0x143,
                0x143: 0x145,
                0x145: 0x14b,
            },
        },
        "data": {
            "blocks": None,
        },
    }
