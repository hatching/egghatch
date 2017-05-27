# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

class BranchException(Exception):
    pass

class Branch(object):
    def __init__(self, ins):
        self.ins = ins
        self.target = None

    def is_relative_branch(self):
        if not self.is_branch():
            raise BranchException("not a branch instruction")

        if self.is_conditional():
            self.ret_to = self.ins.address + len(self.ins.bytes)

        if self.ins.op_str.startswith("0x"):
            self.target = int(self.ins.op_str[2:], 16)
            return True
        else:
            self.target = None
            return False

    def is_branch(self):
        return self.ins.mnemonic in (
            "call", "jmp", "jl", "je", "jne", "jecxz"
        )

    def is_conditional(self):
        return self.ins.mnemonic in (
            "jl", "je", "jne", "jecxz"
        )

    def children(self):
        target, ret_to = self.target, None
        if self.is_conditional():
            ret_to = self.ret_to
        return target, ret_to
