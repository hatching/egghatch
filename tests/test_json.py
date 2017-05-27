# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file "docs/LICENSE" for copying permission.

import json
import mock

from egghatch.shellcode import Shellcode

def test_sd():
    sc = Shellcode(open("tests/files/plain/sd.bin", "rb").read())
    assert json.loads(sc.to_json()) == {
        "text": {
            "0": [
                [0, "xor", "eax, eax"],
                [2, "xor", "ebx, ebx"],
                [4, "mov", "al, 2"],
                [6, "int", "0x80"],
                [8, "cmp", "eax, ebx"],
                [10, "jne", "0x39"],
            ],
            "12": [
                [12, "xor", "eax, eax"],
                [14, "push", "eax"],
                [15, "push", "0x462d"],
                [19, "mov", "esi, esp"],
                [21, "push", "eax"],
                [22, "push", "0x73656c62"],
                [27, "push", "0x61747069"],
                [32, "push", "0x2f6e6962"],
                [37, "push", "0x732f2f2f"],
                [42, "mov", "ebx, esp"],
                [44, "lea", "edx, dword ptr [esp + 0x10]"],
                [48, "push", "eax"],
                [49, "push", "esi"],
                [50, "push", "esp"],
                [51, "mov", "ecx, esp"],
                [53, "mov", "al, 0xb"],
                [55, "int", "0x80"],
            ],
            "57": [
                [57, "mov", "ebx, eax"],
                [59, "xor", "eax, eax"],
                [61, "xor", "ecx, ecx"],
                [63, "xor", "edx, edx"],
                [65, "mov", "al, 7"],
                [67, "int", "0x80"],
            ],
        },
        "data": [],
    }

def test_bin1():
    sc = Shellcode(open("tests/files/plain/1.bin", "rb").read())
    assert json.loads(sc.to_json()) == {
        "text": mock.ANY,
        "data": [
            # TODO See also the TODO items in test_blocks.
            [0x06, mock.ANY],
            [0xb9, "/282yG\x00"],
            [0x14b, "www.service.chrome-up.date\x00"],
        ],
    }
