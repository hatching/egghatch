# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

import mock

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
            "blocks": {},
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
            "blocks": {
                # TODO Implement additional instruction tracking; we must
                # identify the "call 0x88" -> "pop ebp" sequence in
                # combination with "call ebp" instructions later on and
                # determine that the address in ebp (@ offset 6) is also code.
                6: mock.ANY,
                0xb9: "/282yG\x00",
                0x14b: "www.service.chrome-up.date\x00",
            },
        },
    }
