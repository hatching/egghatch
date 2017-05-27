# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

from egghatch import parse, as_text

def test_parse():
    assert parse("\xfc\xeb\xfe") == {
        "bbl": [
            (0, 3),
        ],
        "text": [
            (0, "cld", ""),
            (1, "jmp", "1"),
        ],
        "data": [],
    }

def test_as_text_cld_jmpinf():
    assert as_text("\xfc\xeb\xfe") == (
        "bbl_0x0000:\n"
        "    0x0000: cld\n"
        "    0x0001: jmp 1\n"
    )

def test_as_text_sc():
    def f(filename):
        return open("tests/files/plain/%s" % filename, "rb").read()

    assert as_text(f("1.bin")) == f("1.bin.txt")
    assert as_text(f("2.bin")) == f("2.bin.txt")
    assert as_text(f("3.bin")) == f("3.bin.txt")
