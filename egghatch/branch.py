# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

class Branch:
    def __init__(self, ins):
        self.target = int(ins.op_str.encode()[2:], 16)
        self.ret_to = ins.address + len(ins.bytes)
    
    def children(self):
        return (self.target, self.ret_to)


# TODO: implement all opcodes and get offset
def is_branch(i):
    return i.mnemonic in ["call", "jmp", "jl", "jne", "jecxz"]

