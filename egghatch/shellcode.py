# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

import capstone
import json

from egghatch.block import Block

class Shellcode(object):
    def __init__(self, payload):
        self.parser = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.parser.detail = True
        self.insns = []
        self.bbl = {}
        self.data = {}

        self.payload = payload
        self.parsed = {}

    def analyze(self):
        # Split executable code into basic blocks.
        self.basic_blocks(0)
        self.basic_taint()

        # Extract untouched bytes as data strings.
        self.extract_data()

    def to_dict(self):
        ret = {
            "bbl": [],
            "text": [],
            "data": [],
        }
        self.analyze()
        ret["bbl"] = sorted(self.bbl.items())
        ret["text"] = sorted(self.insns)
        for idx, data in sorted(self.data.items()):
            ret["data"].append((idx, data.decode("latin1")))
        return ret

    def to_json(self):
        return json.dumps(self.to_dict(), indent=4)

    def handle_relative_call(self, block):
        """Handles call/pop sequences where bytes after a call instruction are
        data rather than actual code. This is often used in shellcode to get
        the address of data such as a domain name or URL."""
        insn = block.insns[-1]

        if insn.mnemonic != "call" or block.target is None:
            return

        # Ensure that this is a legitimate call instruction. May go both
        # forward as well as backwards (although backwards is more common
        # provided that allows for proper shellcode without null bytes).
        if block.target > len(self.payload):
            return

        # By default assume that the data behind a relative call is data.
        block.fallthrough = False

    def add_bbl(self, start, end):
        bbl_r = dict((v, k) for k, v in self.bbl.items())
        for start_, end_ in self.bbl.items():
            if start >= start_ and start < end_:
                self.bbl[start_] = start
                self.bbl[start] = end_
                break
            if start < start_ and end == end_:
                self.bbl[start] = bbl_r.get(start_, start_)
                break
            if end and end > start_ and end <= end_:
                self.bbl[start] = start_
                self.bbl[start_] = end
                if end != end_:
                    self.bbl[end] = end_
                break
        else:
            self.bbl[start] = start if end is None else end

    def basic_blocks(self, offset):
        if offset in self.parsed:
            self.add_bbl(offset, None)
            return

        if offset >= len(self.payload):
            return

        block = Block(self)
        if not block.parse(self.payload, offset):
            return

        for insn in block.insns:
            if insn.addr not in self.parsed:
                self.insns.append(insn)

            self.parsed[insn.addr] = False

        self.add_bbl(block.base, block.end)

        # If the last instruction is a call instruction then check if its
        # target is earlier than its address and if it is a pop instruction or
        # sequence. If so, it's likely additional data.
        self.handle_relative_call(block)

        if block.target is not None:
            self.basic_blocks(block.target)

        if block.fallthrough:
            self.basic_blocks(block.end)

    def basic_taint(self):
        """Implements basic taint tracking to handle certain scenarios."""
        insns = {}
        for insn in self.insns:
            insns[insn.addr] = insn

        # If this is a call/pop where the pop'd value is later call'd then the
        # "data" behind the call instruction is actually code.
        for insn1 in self.insns:
            if insn1.mnemonic != "call":
                continue

            op = insn1.operands
            if not op.startswith("0x") and not op.isdigit():
                continue

            target = int(op, 0)
            if target not in insns:
                continue

            insn2 = insns[target]
            if insn2.mnemonic != "pop":
                continue

            op = insn2.operands
            for _ in xrange(64):
                if insn2.addr + insn2.size not in insns:
                    break

                insn2 = insns[insn2.addr + insn2.size]
                if insn2.mnemonic == "call" and insn2.operands == op:
                    self.basic_blocks(insn1.addr + 5)
                    break

    def extract_data(self):
        parsed = {}

        # By iterating in reverse order we can append each basic block end to
        # its next basic block start - assuming they're the same.
        for start, end in sorted(self.bbl.items(), reverse=True):
            parsed[start] = parsed.pop(end, end)

        # End terminator (if there's trailing data).
        parsed[len(self.payload)] = len(self.payload)

        chunks = sorted(parsed.items())
        for idx in xrange(1, len(chunks)):
            _, start = chunks[idx-1]
            end, _ = chunks[idx]
            if start != end and start < end:
                self.data[start] = self.payload[start:end]
