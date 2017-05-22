# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from branch import Branch, is_branch

class Shellcode:
    def __init__(self, payload):
        self.parser = Cs(CS_ARCH_X86, CS_MODE_32)
        self.payload = str(payload)
        self.parsed = {}
        self.text = []

    def analyze(self):
        # split executable code into basic blocks
        self.text = self.basic_blocks(0)
        # extract untouched bytes as data strings
        self.data = self.extract_data()

        for block in self.text:
            self.print_block(block)

    # TODO: define json output format for demo
    def print_block(self, block):
        print "-" * 80
        for i in block:
            print "0x%04x: \t%s\t%s" % \
                (i.address, i.mnemonic, i.op_str)
        print "-" * 80

    # recursively disassemble basic blocks
    def basic_blocks(self, pos):
        block, branch = self.get_block(pos)

        # only traverse further for new blocks
        if not self.parsed.get(pos, False):
            self.text.append(block)
            self.parsed[pos] = True

            # recurse branch target(s)
            if branch:
                self.basic_blocks(branch.target)
                self.basic_blocks(branch.ret_to)

        return self.text

    # disassemble until next branch instruction
    def get_block(self, pos):
        block, branch = [], None
        for i in self.parser.disasm(self.payload[pos:], pos):
            block.append(i)
            if is_branch(i):
                try :
                    branch = Branch(i)
                    break
                except ValueError:
                    continue
        return (block, branch)
        
    # TODO: extract untouched bytes as data strings
    def extract_data(self):
        return "hax\n"
