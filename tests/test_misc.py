# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

from egghatch.misc import str_as_db


def test_str_as_db():
    assert str_as_db("\x00") == "0"
    assert str_as_db("foo") == "'foo'"
    assert str_as_db("bar\x00") == "'bar',0"
    assert str_as_db("foo\x00baz\x01") == "'foo',0,'baz',1"
