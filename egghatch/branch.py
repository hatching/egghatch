# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

class BranchException(Exception):
    pass

class Branch(object):
    def __init__(self, ins):
        self.ins = ins
        if not self.is_branch():
            raise BranchException("not a branch instruction")

        # TODO: this is hacky
        self.target = int(ins.op_str.encode()[2:], 16)
        if self.is_conditional():
            self.ret_to = ins.address + len(ins.bytes)

    # TODO: this is hacky
    def is_branch(self):
        return self.ins.mnemonic in ["call", "jmp", "jl", "jne", "jecxz"]

    # TODO: this is hacky
    def is_conditional(self):
        return self.ins.mnemonic in ["jl", "jne", "jecxz"]

    def children(self):
        target, ret_to = self.target, None
        if self.is_conditional():
            ret_to = self.ret_to
        return target, ret_to
