# sample run

```
➜  egghatch-basic-blocks git:(master) cat tests/files/plain/sd.bin | egghatch
{
    "0": {
        "0": {
            "arg": "eax, eax", 
            "ins": "xor"
        }, 
        "2": {
            "arg": "ebx, ebx", 
            "ins": "xor"
        }, 
        "4": {
            "arg": "al, 2", 
            "ins": "mov"
        }, 
        "6": {
            "arg": "0x80", 
            "ins": "int"
        }, 
        "8": {
            "arg": "eax, ebx", 
            "ins": "cmp"
        }, 
        "10": {
            "arg": "0x39", 
            "ins": "jne"
        }
    }, 
    "57": {
        "65": {
            "arg": "al, 7", 
            "ins": "mov"
        }, 
        "67": {
            "arg": "0x80", 
            "ins": "int"
        }, 
        "57": {
            "arg": "ebx, eax", 
            "ins": "mov"
        }, 
        "59": {
            "arg": "eax, eax", 
            "ins": "xor"
        }, 
        "61": {
            "arg": "ecx, ecx", 
            "ins": "xor"
        }, 
        "63": {
            "arg": "edx, edx", 
            "ins": "xor"
        }
    }, 
    "12": {
        "32": {
            "arg": "0x2f6e6962", 
            "ins": "push"
        }, 
        "51": {
            "arg": "ecx, esp", 
            "ins": "mov"
        }, 
        "37": {
            "arg": "0x732f2f2f", 
            "ins": "push"
        }, 
        "44": {
            "arg": "edx, dword ptr [esp + 0x10]", 
            "ins": "lea"
        }, 
        "42": {
            "arg": "ebx, esp", 
            "ins": "mov"
        }, 
        "12": {
            "arg": "eax, eax", 
            "ins": "xor"
        }, 
        "14": {
            "arg": "eax", 
            "ins": "push"
        }, 
        "15": {
            "arg": "0x462d", 
            "ins": "push"
        }, 
        "48": {
            "arg": "eax", 
            "ins": "push"
        }, 
        "49": {
            "arg": "esi", 
            "ins": "push"
        }, 
        "50": {
            "arg": "esp", 
            "ins": "push"
        }, 
        "19": {
            "arg": "esi, esp", 
            "ins": "mov"
        }, 
        "21": {
            "arg": "eax", 
            "ins": "push"
        }, 
        "22": {
            "arg": "0x73656c62", 
            "ins": "push"
        }, 
        "55": {
            "arg": "0x80", 
            "ins": "int"
        }, 
        "27": {
            "arg": "0x61747069", 
            "ins": "push"
        }, 
        "53": {
            "arg": "al, 0xb", 
            "ins": "mov"
        }
    }
}
```
