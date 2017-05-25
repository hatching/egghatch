# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

import pytest
from egghatch.shellcode import Shellcode
import json


def test_sd():
    # http://shell-storm.org/shellcode/files/shellcode-554.php
    with open('files/plain/sd.bin') as sd:
        sc = Shellcode(sd.read())

    assert json.loads(sc.print_json()) == {
        '0' : {
            '0': {u'arg': u'eax, eax', u'ins': u'xor'},
            '2' : {u'arg': u'ebx, ebx', u'ins': u'xor'},
            '4' : {u'arg': u'al, 2', u'ins': u'mov'},
            '6' : {u'arg': u'0x80', u'ins': u'int'},
            '8':  {u'arg': u'eax, ebx', u'ins': u'cmp'},
            '10': {u'arg': u'0x39', u'ins': u'jne'},
        },
        '12': {
            '12': {u'arg': u'eax, eax', u'ins': u'xor'},
            '14': {u'arg': u'eax', u'ins': u'push'},
            '15': {u'arg': u'0x462d', u'ins': u'push'},
            '19': {u'arg': u'esi, esp', u'ins': u'mov'},
            '21': {u'arg': u'eax', u'ins': u'push'},
            '22': {u'arg': u'0x73656c62', u'ins': u'push'},
            '27': {u'arg': u'0x61747069', u'ins': u'push'},
            '32': {u'arg': u'0x2f6e6962', u'ins': u'push'},
            '37': {u'arg': u'0x732f2f2f', u'ins': u'push'},
            '42': {u'arg': u'ebx, esp', u'ins': u'mov'},
            '44': {u'arg': u'edx, dword ptr [esp + 0x10]', u'ins': u'lea'},
            '48': {u'arg': u'eax', u'ins': u'push'},
            '49': {u'arg': u'esi', u'ins': u'push'},
            '50': {u'arg': u'esp', u'ins': u'push'},
            '51': {u'arg': u'ecx, esp', u'ins': u'mov'},
            '53': {u'arg': u'al, 0xb', u'ins': u'mov'},
            '55': {u'arg': u'0x80', u'ins': u'int'}
        },
        '57': {
            '57': {u'arg': u'ebx, eax', u'ins': u'mov'},
            '59': {u'arg': u'eax, eax', u'ins': u'xor'},
            '61': {u'arg': u'ecx, ecx', u'ins': u'xor'},
            '63': {u'arg': u'edx, edx', u'ins': u'xor'},
            '65': {u'arg': u'al, 7', u'ins': u'mov'},
            '67': {u'arg': u'0x80', u'ins': u'int'}
        }
    }
