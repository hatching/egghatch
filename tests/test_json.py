# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file "docs/LICENSE" for copying permission.

import json

from egghatch.shellcode import Shellcode

def test_sd():
    # http://shell-storm.org/shellcode/files/shellcode-554.php
    with open("tests/files/plain/sd.bin") as sd:
        sc = Shellcode(sd.read())

    assert json.loads(sc.to_json()) == {
        "0": {
            "0": {"arg": "eax, eax", "ins": "xor"},
            "2": {"arg": "ebx, ebx", "ins": "xor"},
            "4": {"arg": "al, 2", "ins": "mov"},
            "6": {"arg": "0x80", "ins": "int"},
            "8": {"arg": "eax, ebx", "ins": "cmp"},
            "10": {"arg": "0x39", "ins": "jne"},
        },
        "12": {
            "12": {"arg": "eax, eax", "ins": "xor"},
            "14": {"arg": "eax", "ins": "push"},
            "15": {"arg": "0x462d", "ins": "push"},
            "19": {"arg": "esi, esp", "ins": "mov"},
            "21": {"arg": "eax", "ins": "push"},
            "22": {"arg": "0x73656c62", "ins": "push"},
            "27": {"arg": "0x61747069", "ins": "push"},
            "32": {"arg": "0x2f6e6962", "ins": "push"},
            "37": {"arg": "0x732f2f2f", "ins": "push"},
            "42": {"arg": "ebx, esp", "ins": "mov"},
            "44": {"arg": "edx, dword ptr [esp + 0x10]", "ins": "lea"},
            "48": {"arg": "eax", "ins": "push"},
            "49": {"arg": "esi", "ins": "push"},
            "50": {"arg": "esp", "ins": "push"},
            "51": {"arg": "ecx, esp", "ins": "mov"},
            "53": {"arg": "al, 0xb", "ins": "mov"},
            "55": {"arg": "0x80", "ins": "int"},
        },
        "57": {
            "57": {"arg": "ebx, eax", "ins": "mov"},
            "59": {"arg": "eax, eax", "ins": "xor"},
            "61": {"arg": "ecx, ecx", "ins": "xor"},
            "63": {"arg": "edx, edx", "ins": "xor"},
            "65": {"arg": "al, 7", "ins": "mov"},
            "67": {"arg": "0x80", "ins": "int"},
        },
    }
