# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

from egghatch import parse, as_text

def test_parse():
    assert parse(b"\xfc\xeb\xfe") == {
        "bbl": [
            (0, 1),
            (1, 3),
        ],
        "text": [
            (0, 1, "cld", ""),
            (1, 2, "jmp", "1"),
        ],
        "data": [],
    }

def test_as_text_cld_jmpinf():
    assert as_text(b"\xfc\xeb\xfe") == (
        "bbl_0x0000:\n"
        "    0x0000: cld\n"
        "bbl_0x0001:\n"
        "    0x0001: jmp 1\n"
    )

def test_as_text_sc():
    def f(filename):
        return open("tests/files/plain/%s" % filename, "rb").read()

    assert f("1.bin.txt").decode("utf-8") == as_text(f("1.bin"))
    assert f("2.bin.txt").decode("utf-8") == as_text(f("2.bin"))
    assert f("3.bin.txt").decode("utf-8") == as_text(f("3.bin"))
