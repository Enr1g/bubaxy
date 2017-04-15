#!/usr/bin/env python3 -u
from serviceproxy import ServiceProxy
from bushloop import BushLoop
import argparse
import logging
import socket
import sys


EPILOG = """Example:
Wrap ssh on bushwhackers.ru and listen at 31337:

\t./bubaxy.py --patterns patterns.yaml --net bushwhackers.ru:22 -p 31337 --level=DEBUG
"""

# Or logging.getLogger(sys.argv[0]) every time? Nah, fuck it
logger = None

async def master_socket_handler(loop, master_socket):
    while True:
        sock, _ = await loop.sock_accept(master_socket)

        try:
            ServiceProxy(sock, service_type, target, loop)
        except ConnectionRefusedError as e:
            logger.warning("%s: %s", e, target)
            sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        sys.argv[0],
        formatter_class=argparse.RawTextHelpFormatter,
        description="IO wrapper for arbitrary executables.",
        epilog=EPILOG
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--cmd', metavar='command', type=str, help="A command to execute")
    group.add_argument('--net', metavar='host:port', type=str, help="Host and port to connect")

    parser.add_argument('--patterns', type=str, required=False, default=None,
                        help="Path to the file with patterns to ban")

    parser.add_argument('-c', '--chunk-size', type=int, required=False, default=1024, help="Chunk size for socket I/O")
    parser.add_argument('-p', '--port', type=int, required=True, help="Port for wrapper to listen")
    parser.add_argument('-l', '--level', type=str, required=False, help="Log level. DON'T USE DEBUG ON CTF!")

    args = parser.parse_args()

    logger = logging.getLogger(sys.argv[0])
    _ = logging.StreamHandler()
    _.setFormatter(logging.Formatter('[ %(asctime)s ][%(levelname)s]: %(message)s'))
    logger.addHandler(_)

    try:
        logger.setLevel(args.level.upper())
    except:
        logger.setLevel(logging.INFO)

    if args.net:
        target = args.net.split(':')
        assert len(target) == 2
        target[1] = int(target[1])
        target = tuple(target)
        service_type = 'net'
    else:
        target = args.cmd
        service_type = 'cmd'

    logger.info(args)

    master_socket = socket.socket()
    master_socket.setblocking(0)
    master_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    master_socket.bind(('127.0.0.1', args.port))
    master_socket.listen(1000)

    loop = BushLoop()
    ServiceProxy.set_chunk_size(args.chunk_size)
    ServiceProxy.update_patterns(args.patterns)

    def evaler():
        cmd = sys.stdin.readline()
        code = compile(cmd, '<input>', 'single')
        eval(code, globals(), globals())

    loop.add_reader(sys.stdin.fileno(), evaler)

    loop.run_until_complete(master_socket_handler(loop, master_socket))
