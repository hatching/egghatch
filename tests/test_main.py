# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

from egghatch import parse

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
