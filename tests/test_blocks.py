# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

from egghatch.shellcode import Shellcode

def test_sd():
    # http://shell-storm.org/shellcode/files/shellcode-554.php
    with open("tests/files/plain/sd.bin") as sd:
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
