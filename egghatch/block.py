# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

import collections

Instruction = collections.namedtuple(
    "Instruction", ("addr", "size", "mnemonic", "operands")
)

class Block(object):
    stop_insns = (
        "jmp", "jecxz", "ret", "loop", "loope", "loopne",
        "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
        "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
    )
    conditional_jmps = (
        "jecxz", "loope", "loopne",
        "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
        "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
    )
    no_fallthrough_insns = "ret", "jmp"

    def __init__(self, parent):
        self.parent = parent
        self.base = None
        self.end = None
        self.insns = []
        self.target = None
        self.fallthrough = None

    def parse(self, stream, offset, addr=None):
        self.base = offset
        p = self.parent.parser.disasm_lite(stream[offset:], addr or offset)
        for addr, size, mnemonic, operands in p:
            self.insns.append(Instruction(addr, size, mnemonic, operands))
            if mnemonic in self.stop_insns:
                break
            if mnemonic == "call" and self.addr(operands) is not None:
                break
        else:
            # No instructions have been decoded.
            if not self.insns:
                return False

        self.end = addr + size
        self.fallthrough = mnemonic not in self.no_fallthrough_insns
        self.target = self.addr(operands)
        return True

    def to_dict(self):
        ret = []
        for addr, size, mnemonic, operands in self.insns:
            ret.append((addr, mnemonic, operands))
        return ret

    def addr(self, target):
        if target.startswith("0x") or target.isdigit():
            return int(target, 0)
