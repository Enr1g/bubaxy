# bubaxy

## Description

bubaxy stands for Bushwhackers Ban Proxy.

## Usage

```
usage: ./bubaxy.py [-h] (--cmd command | --net host:port)
                   [--patterns PATTERNS] [-c CHUNK_SIZE] -p PORT [-l LEVEL]

IO wrapper for arbitrary executables.

optional arguments:
  -h, --help            show this help message and exit
  --cmd command         A command to execute
  --net host:port       Host and port to connect
  --patterns PATTERNS   Path to the file with patterns to ban
  -c CHUNK_SIZE, --chunk-size CHUNK_SIZE
                        Chunk size for socket I/O
  -p PORT, --port PORT  Port for wrapper to listen
  -l LEVEL, --level LEVEL
                        Log level. DON'T USE DEBUG ON CTF!

Example:
Wrap ssh on bushwhackers.ru and listen at 31337:

  ./bubaxy.py --patterns patterns.yaml --net bushwhackers.ru:22 -p 31337 --level=DEBUG
```

## Ban substrings and regular expressions

### Configuration file format

*Hint*: use single quote to enclose raw strings in YAML, e.g. `'\n'` will be interpreted as `r"\n"` in python

#### Section `conf`

- `max_len` - maximum length of a pattern to ban. Possible values: `auto`, positive number

#### Section `patterns`

- `plain` - list of plaintext patterns to ban.
- `python` - list of python literals, e.g. `'\x0c\x0b\x0a'`.
- `hex` - list of hex encoded patterns, e.g. `'61616161'`.
- `base64` - list of base64 encoded patterns, e.g. `'QnVzaHdoYWNrZXJz'`
- `regexp` - list of python regular expressions. Keep in mind, that bad regular expressions, like `(a+)+` can affect a performance dramatically. Also regular expressions have a **limited support** because of bufferization.
