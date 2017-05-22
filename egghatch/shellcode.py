# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

class Shellcode:
    def __init__(self, payload):
        self.parser = Cs(CS_ARCH_X86, CS_MODE_32)
        self.payload = str(payload)

    def analyze(self):
        # split executable code into basic blocks
        self.text = self.basic_blocks()
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

    # TODO: implement recursive block disassembly
    def basic_blocks(self):
        blocks = []
        block = []
        for i in self.parser.disasm(self.payload, 0):
            block.append(i)
            if self.is_branch(i):
                break
        blocks.append(block)
        return blocks   

    # TODO: implement all opcodes and get offset
    def is_branch(self, i):
        return i.mnemonic in ["call", "jmp"]

    # TODO: extract untouched bytes as data strings
    def extract_data(self):
        return "hax\n"
