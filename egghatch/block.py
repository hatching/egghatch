# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

class Block(object):
    def __init__(self, parent, base, end):
        self.parent = parent
        self.base = base
        self.end = end

    def to_dict(self):
        ret, payload = [], self.parent.payload[self.base:self.end]
        for ins in self.parent.parser.disasm(payload, self.base):
            ret.append((ins.address, ins.mnemonic, ins.op_str))
        return ret
