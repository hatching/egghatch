# sample run

```
➜  egghatch-basic-blocks git:(master) cat tests/files/plain/sd.bin | egghatch; cd tests && python -m pytest
[+] code block [0x0000 - 0x000c]
[+] code block [0x0039 - 0x0045]
[+] code block [0x000c - 0x0039]
==================================== test session starts =====================================
platform linux2 -- Python 2.7.12+, pytest-3.1.0, py-1.4.33, pluggy-0.4.0
rootdir: /home/user/src/egghatch-basic-blocks, inifile:
collected 1 items

test_blocks.py .

================================== 1 passed in 0.02 seconds ==================================
```
