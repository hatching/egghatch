# sample run

```
➜  egghatch-basic-blocks git:(master) cat tests/files/plain/sd.bin | egghatch; cd tests && python -m pytest
0x0000: 	xor	eax, eax
0x0002: 	xor	ebx, ebx
0x0004: 	mov	al, 2
0x0006: 	int	0x80
0x0008: 	cmp	eax, ebx
0x000a: 	jne	0x39
--------------------------------------------------------------------------------
0x0039: 	mov	ebx, eax
0x003b: 	xor	eax, eax
0x003d: 	xor	ecx, ecx
0x003f: 	xor	edx, edx
0x0041: 	mov	al, 7
0x0043: 	int	0x80
--------------------------------------------------------------------------------
0x000c: 	xor	eax, eax
0x000e: 	push	eax
0x000f: 	push	0x462d
0x0013: 	mov	esi, esp
0x0015: 	push	eax
0x0016: 	push	0x73656c62
0x001b: 	push	0x61747069
0x0020: 	push	0x2f6e6962
0x0025: 	push	0x732f2f2f
0x002a: 	mov	ebx, esp
0x002c: 	lea	edx, dword ptr [esp + 0x10]
0x0030: 	push	eax
0x0031: 	push	esi
0x0032: 	push	esp
0x0033: 	mov	ecx, esp
0x0035: 	mov	al, 0xb
0x0037: 	int	0x80
--------------------------------------------------------------------------------
============================================================================================================================= test session starts ==============================================================================================================================
platform linux2 -- Python 2.7.12+, pytest-3.1.0, py-1.4.33, pluggy-0.4.0
rootdir: /home/user/src/egghatch-basic-blocks, inifile:
collected 1 items

test_blocks.py .

=========================================================================================================================== 1 passed in 0.02 seconds ===========================================================================================================================

```
