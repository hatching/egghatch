# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

from egghatch.shellcode import Shellcode


def test_parse():
    sc = Shellcode(b"\x90\x75\x02\x90\x90\x90")
    assert sc.to_dict() == {
        "text": [
            (0, 1, "nop", ""),
            (1, 2, "jne", "5"),
            (3, 1, "nop", ""),
            (4, 1, "nop", ""),
            (5, 1, "nop", ""),
        ],
        "bbl": [
            (0x00, 0x03),
            (0x03, 0x05),
            (0x05, 0x06),
        ],
        "data": [],
    }


def test_add_bbl1():
    sc = Shellcode("")
    sc.parsed[97] = False
    sc.parsed[129] = False
    sc.parsed[130] = False
    sc.parsed[136] = False
    sc.add_bbl(136, 192)
    sc.add_bbl(130, 136)
    sc.add_bbl(129, 136)
    sc.add_bbl(97, 129)
    assert sc.bbl == {
        97: 129,
        129: 130,
        130: 136,
        136: 192,
    }


def test_add_bbl2():
    sc = Shellcode("")
    sc.parsed[209] = False
    sc.parsed[249] = False
    sc.parsed[256] = True
    sc.parsed[290] = False
    sc.add_bbl(209, 244)
    sc.add_bbl(256, 308)
    sc.add_bbl(249, 308)
    sc.add_bbl(290, None)
    sc.add_bbl(249, 308)
    sc.add_bbl(290, None)
    assert sc.bbl == {
        209: 244,
        249: 256,
        256: 290,
        290: 308,
    }


def test_sd():
    sc = Shellcode(open("tests/files/plain/sd.bin", "rb").read())
    assert sc.to_dict()["bbl"] == [
        (0x00, 0x0c),
        (0x0c, 0x39),
        (0x39, 0x45),
    ]


def test_bin1():
    sc = Shellcode(open("tests/files/plain/1.bin", "rb").read())
    assert sc.to_dict()["bbl"] == [
        (0x00, 0x06),
        (0x06, 0x15),
        (0x15, 0x1e),
        (0x1e, 0x23),
        (0x23, 0x25),
        (0x25, 0x2c),
        (0x2c, 0x3a),
        (0x3a, 0x45),
        (0x45, 0x47),
        (0x47, 0x4f),
        (0x4f, 0x59),
        (0x59, 0x61),
        (0x61, 0x81),
        (0x81, 0x82),
        (0x82, 0x88),
        (0x88, 0xb9),
        (0xc0, 0xe1),
        (0xe1, 0x105),
        (0x105, 0x108),
        (0x108, 0x10f),
        (0x10f, 0x128),
        (0x128, 0x13b),
        (0x13b, 0x143),
        (0x143, 0x145),
        (0x145, 0x14b),
    ]
    assert sc.to_dict()["data"] == [
        (0xb9, "/282yG\x00"),
        (0x14b, "www.service.chrome-up.date\x00"),
    ]


def test_bin2():
    sc = Shellcode(open("tests/files/plain/2.bin", "rb").read())
    assert sc.to_dict()["bbl"] == [
        (0x00, 0x06),
        (0x06, 0x15),
        (0x15, 0x1e),
        (0x1e, 0x23),
        (0x23, 0x25),
        (0x25, 0x2c),
        (0x2c, 0x3a),
        (0x3a, 0x45),
        (0x45, 0x47),
        (0x47, 0x4f),
        (0x4f, 0x59),
        (0x59, 0x61),
        (0x61, 0x81),
        (0x81, 0x82),
        (0x82, 0x88),
        (0x88, 0xc0),
        (0xd1, 0xe5),
        (0xe5, 0xf4),
        (0xf4, 0xf9),
        (0xf9, 0x100),
        (0x100, 0x122),
        (0x122, 0x134),
        (0x134, 0x135),
    ]
    assert sc.to_dict()["data"] == [
        (192, "ddos400.ddns.net\x00"),
    ]


def test_bin3():
    sc = Shellcode(open("tests/files/plain/3.bin", "rb").read())
    assert sc.to_dict()["bbl"] == [
        (0x00, 0x06),
        (0x06, 0x15),
        (0x15, 0x1e),
        (0x1e, 0x23),
        (0x23, 0x25),
        (0x25, 0x2c),
        (0x2c, 0x3a),
        (0x3a, 0x45),
        (0x45, 0x47),
        (0x47, 0x4f),
        (0x4f, 0x59),
        (0x59, 0x61),
        (0x61, 0x81),
        (0x81, 0x82),
        (0x82, 0x88),
        (0x88, 0xb9),
        (0xc0, 0xe1),
        (0xe1, 0x105),
        (0x105, 0x108),
        (0x108, 0x10f),
        (0x10f, 0x128),
        (0x128, 0x13b),
        (0x13b, 0x143),
        (0x143, 0x145),
        (0x145, 0x14b),
    ]
    assert sc.to_dict()["data"] == [
        (0xb9, "/BZFC7\x00"),
        (0x14b, "spintoolmid.ddns.net\x00"),
    ]
