Block analysis format is defined in test_blocks.py:

```
    assert sc.analyze() == {
        'text': {
            'blocks': {
                0x00: 0x0c,
                0x0c: 0x39,
                0x39: 0x45
            }
        },
        'data': {
            'blocks': None
        }
    }
```
