# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

import sys

from egghatch.shellcode import Shellcode

def main():
    if len(sys.argv) != 2:
        print "Usage: python %s <sc.bin>" % sys.argv[0]
        exit(1)

    print Shellcode(open(sys.argv[1], "rb").read()).to_json()

def parse(payload):
    return Shellcode(payload).to_dict()
