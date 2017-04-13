# bubaxy

## Description

bubaxy stands for Bushwhackers Ban Proxy.

## Usage

```
usage: ./bubaxy.py [-h] (--cmd command | --net host:port)
                   [--pattern PATTERN | -i INPUT] [-s STR_ENCODING]
                   [-e ENCODING] [-c CHUNK_SIZE] [-m MAX_LEN_OF_PATTERN] -p
                   PORT [-l LEVEL]

IO wrapper for arbitrary executables.

optional arguments:
  -h, --help            show this help message and exit
  --cmd command         A command to execute
  --net host:port       Host and port to connect
  --pattern PATTERN     Ban a substring
  -i INPUT, --input INPUT
                        File with patterns to be banned. Don't forget about transport encodings (e.g. url encoding)!
  -s STR_ENCODING, --str-encoding STR_ENCODING
                        Terminal/file/string encoding. Do not touch if in doubt (default set to utf8)
  -e ENCODING, --encoding ENCODING
                        Representation encoding: base64, hex, etc (from codecs.decode)
  -c CHUNK_SIZE, --chunk-size CHUNK_SIZE
                        Chunk size for socket I/O
  -m MAX_LEN_OF_PATTERN, --max-len-of-pattern MAX_LEN_OF_PATTERN
                        Max length of pattern
  -p PORT, --port PORT  Port for wrapper to listen
  -l LEVEL, --level LEVEL
                        Log level
```

## Examples

* Execute cat and ban substring 'shit' encoded in base64:
`./wrapper.py --pattern 'c2hpdA==' -e base64 --cmd cat -p 31337`
* Execute cat and ban substring 'GET / HTTP/0.9' encoded in hex:
`./wrapper.py --pattern '474554202f20485454502f302e390a' -e hex --cmd cat -p 31337`
* Wrap network service on port 8888 and manually set input cache size to 100:
`./wrapper.py --pattern 'exploit' -b 100 --net 127.0.0.1:8888 -p 31337`
