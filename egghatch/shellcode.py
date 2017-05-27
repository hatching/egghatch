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

        self.payload = payload
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
        ret = {
            "text": {},
            "data": [],
        }
        self.analyze()
        for block in self.text:
            ret["text"][block.base] = block.to_dict()
        for idx, data in sorted(self.data.items()):
            ret["data"].append((idx, data.decode("latin1")))
        return json.dumps(ret, indent=4)

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

    def get_block(self, pos):
        block, branch = None, None
        cur = pos
        for i in self.parser.disasm(self.payload[pos:], pos):
            if cur in self.parsed:
                block = Block(self, pos, cur)
                break
            self.parsed[cur] = True
            cur += len(i.bytes)
            block = Block(self, pos, cur)
            branch = Branch(i)
            if branch.is_branch() and branch.is_relative_branch():
                break

        return block, branch

    def extract_data(self):
        ret, parsed, bbls = {}, {}, []

        for block in self.text:
            bbls.append((block.base, block.end))

        # By iterating in reverse order we can append each basic block end to
        # its next basic block start - assuming they're the same.
        for start, end in sorted(bbls, reverse=True):
            parsed[start] = parsed.pop(end, end)

        # End terminator (if there's trailing data).
        parsed[len(self.payload)] = len(self.payload)

        chunks = sorted(parsed.items())
        for idx in xrange(1, len(chunks)):
            _, start = chunks[idx-1]
            end, _ = chunks[idx]
            if start != end:
                ret[start] = self.payload[start:end]
        return ret
