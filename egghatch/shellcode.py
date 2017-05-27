# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

import capstone
import json

from egghatch.branch import Branch
from egghatch.block import Block

class Shellcode(object):
    def __init__(self, payload):
        self.parser = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.parser.detail = True
        self.text, self.data = [], []

        self.payload = str(payload)
        self.parsed = {}

    def analyze(self):
        # split executable code into basic blocks
        self.text = self.basic_blocks(0)
        # extract untouched bytes as data strings
        self.data = self.extract_data()

        # TODO: use Block class
        code_blocks = {}
        for block in self.text:
            code_blocks[block.base] = block.end

        return {
            "text": {
                "blocks": code_blocks,
            },
            "data": {
                "blocks": self.data,
            },
        }

    def print_block(self, start, end):
        print "[+] code block [0x%04x - 0x%04x]" % (start, end)

    def to_json(self):
        ret = {}
        for start, end in self.analyze()["text"]["blocks"].items():
            ret[start] = self.to_dict(start, end)
        return json.dumps(ret, indent=4)

    # TODO: move this to Block class
    def to_dict(self, start, end):
        ret = {}
        for i in self.parser.disasm(self.payload[start:end], start):
            ret[i.address] = {
                "ins": i.mnemonic, "arg": i.op_str
            }
        return dict(ret)

    # recursively disassemble basic blocks
    def basic_blocks(self, pos):
        block, branch = self.get_block(pos)

        # only traverse further for new blocks
        self.text.append(block)

        # recurse branch target(s)
        if branch:
            for b in branch.children():
                if b is not None and b not in self.parsed:
                    self.basic_blocks(b)

        return self.text

    # disassemble until next branch instruction
    def get_block(self, pos):
        block, branch = None, None
        cur = pos
        for i in self.parser.disasm(self.payload[pos:], pos):
            if cur in self.parsed:
                block = Block(pos, cur)
                break
            self.parsed[cur] = True
            cur += len(i.bytes)
            block = Block(pos, cur)
            branch = Branch(i)
            if branch.is_branch() and branch.is_relative_branch():
                break

        return block, branch

    # TODO: extract untouched bytes as data strings
    def extract_data(self):
        return None
