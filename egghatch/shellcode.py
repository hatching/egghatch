# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from branch import Branch, BranchException
from block import Block


class Shellcode:
    def __init__(self, payload):
        self.parser = Cs(CS_ARCH_X86, CS_MODE_32)
        self.text, self.data = [], []

        self.payload = str(payload)
        self.parsed = {}

    def analyze(self):
        # split executable code into basic blocks
        self.text = self.basic_blocks(0)
        # extract untouched bytes as data strings
        self.data = self.extract_data()

        code_blocks = {}
        for block in self.text:
            code_blocks[block.base] = block.end

        return {
            "text": { "blocks": code_blocks },
            "data": { "blocks": self.data }
        }

    # TODO: define json output format for demo
    def print_block(self, start, end):
        print "[+] code block [0x%04x - 0x%04x]" % (start, end)

    # recursively disassemble basic blocks
    def basic_blocks(self, pos):
        block, branch = self.get_block(pos)

        # only traverse further for new blocks
        if not self.parsed.get(pos, False):
            self.text.append(block)
            self.parsed[pos] = True

            # recurse branch target(s)
            if branch:
                for b in branch.children():
                    self.basic_blocks(b)

        return self.text

    # disassemble until next branch instruction
    def get_block(self, pos):
        block, branch = None, None
        cur = pos
        for i in self.parser.disasm(self.payload[pos:], pos):
            if self.parsed.get(cur, False):
                break
            cur += len(i.bytes)
            block = Block(pos, cur)
            try :
                branch = Branch(i)
                break
            except BranchException:
                continue
            except TypeError:
                # TODO: this is hacky
                continue

        return block, branch
        
    # TODO: extract untouched bytes as data strings
    def extract_data(self):
        return None

