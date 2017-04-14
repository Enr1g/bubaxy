#!/usr/bin/env python3 -u
from servicewrapper import NetworkServiceWrapper, ExecutableServiceWrapper
from bushloop import BushLoop
from codecs import decode
import traceback
import argparse
import asyncio
import logging
import socket
import errno
import sys


EPILOG = """Examples:
- Execute cat and ban substring 'shit' encoded in base64:
\t./wrapper.py --pattern 'c2hpdA==' -e base64 --cmd cat -p 31337
- Execute cat and ban substring 'GET / HTTP/0.9' encoded in hex:
\t./wrapper.py --pattern '474554202f20485454502f302e390a' -e hex --cmd cat -p 31337
- Wrap network service on port 8888 and manually set input cache size to 100:
\t./wrapper.py --pattern 'exploit' -b 100 --net 127.0.0.1:8888 -p 31337
"""

conns = []
# Or logging.getLogger(sys.argv[0]) every time? Nah, fuck it
logger = None


class Service:

    def __init__(self, io_sock, service_type, target, loop, chunk_size=1024, max_len_of_pattern=100, patterns=None):
        if service_type == 'net':
            self.service = NetworkServiceWrapper(target, loop)
        elif service_type == 'cmd':
            self.service = ExecutableServiceWrapper(target)
        else:
            raise Exception("Unknown Service Type")

        self.chunk_size = chunk_size
        self.max_len_of_pattern = max_len_of_pattern

        self.io_sock = io_sock
        self.io_fno = io_sock.fileno()
        self.io_sock.setblocking(0)

        self.loop = loop
        self.storing = bool(patterns)

        self.buffer_in = bytearray(2 * chunk_size + max_len_of_pattern)
        self.mbuffer_in = memoryview(self.buffer_in)
        self.buffer_out = bytearray(chunk_size)
        self.mbuffer_out = memoryview(self.buffer_out)
        self.patterns = patterns

        self.to_service_task = asyncio.Task(self.to_service())
        self.from_service_task = asyncio.Task(self.from_service())

        self.loop.create_task(self.disposer())

        logger.info("%s was spawned" % self.service)

    async def disposer(self):
        # TODO: QUESTIONABLE DECISION: Is disposal guaranteed?
        try:
            await self.to_service_task
        except Exception as e:
            logger.warning(e)
            traceback.print_stack()

        try:
            await self.from_service_task
        except Exception as e:
            logger.warning(e)
            traceback.print_stack()

        self.dispose()

    async def to_service(self):
        while True:
            # awaitable can throw an exception
            try:
                nbytes = await self.loop.sock_recv_into(self.io_sock, self.mbuffer_in[-self.chunk_size:], self.chunk_size)
            except Exception as e:
                nbytes = 0
                logger.warning(e)
                traceback.print_stack()

            # Got nothing, looks like eof
            if nbytes == 0:
                self.service.close_in()
                return

            # Processing
            self.mbuffer_in[:-nbytes] = self.mbuffer_in[nbytes:]

            # Looking for a bad pattern
            if self.storing and self.patterns:
                for pattern in self.patterns:
                    # Actually, not from 0
                    if self.buffer_in.find(pattern, 0, self.chunk_size + self.max_len_of_pattern) > -1:
                        logger.info('Banned %s from %s' % (pattern, self.service))

                        try:
                            self.service.close_in_out()
                        except Exception as e:
                            logger.warning(e)
                            traceback.print_stack()

                        try:
                            self.io_sock.shutdown(socket.SHUT_RDWR)
                        except OSError as e:
                            # [Errno 57] Socket is not connected
                            if e.errno != errno.ENOTCONN:
                                logger.warning(e)
                                traceback.print_stack()

                        return

            # Optimizing logging
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("%s received: %s", self.service,
                             self.buffer_in[-self.chunk_size - nbytes: -self.chunk_size])

            try:
                # send or sendall?
                await self.service.write(self.mbuffer_in[-self.chunk_size - nbytes: -self.chunk_size])
            except Exception as exp:
                try:
                    # TODO: QUESTIONABLE DECISION: Why SHUT_RD?
                    self.io_sock.shutdown(socket.SHUT_RD)
                except OSError as e:
                    # [Errno 57] Socket is not connected
                    if e.errno != errno.ENOTCONN:
                        # Don't forget about an old exception
                        logger.warning(exp)
                        traceback.print_stack()
                        raise e
                raise exp

    async def from_service(self):
        while True:
            # awaitable can throw an exception
            try:
                nbytes = await self.service.read_into(self.mbuffer_out, self.chunk_size)
            except Exception as e:
                nbytes = 0
                logger.warning(e)
                traceback.print_stack()

            # Got nothing, looks like eof
            if nbytes == 0:
                try:
                    # TODO: QUESTIONABLE DECISION: Why SHUT_WR?
                    self.io_sock.shutdown(socket.SHUT_WR)
                except OSError as e:
                    # [Errno 57] Socket is not connected
                    if e.errno != errno.ENOTCONN:
                        raise e
                return

            # Optimizing logging
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("%s produced: %s", self.service, self.buffer_out[:nbytes])
            try:
                await self.loop.sock_sendall(self.io_sock, self.mbuffer_out[:nbytes])
            except Exception as e:
                # TODO: QUESTIONABLE DECISION: Can we do something smarter?
                # we didn't manage to send all data
                self.service.close_out()

    def dispose(self):
        logger.info('%s was disposed' % self.service)

        self.service.close()
        
        try:
            idx = conns.index(self)
            conns.pop(idx)
        except Exception as e:
            logger.warning(e)
            traceback.print_stack()

        # asyncio surprisingly can fuck you w/o this step
        self.loop.remove_reader(self.io_fno)
        self.io_sock.close()


async def master_socket_handler(loop, master_socket, chunk_size, max_len_of_pattern, patterns):
    while True:
        sock, _ = await loop.sock_accept(master_socket)

        try:
            service = Service(sock, service_type, target, loop, chunk_size, max_len_of_pattern, patterns)
        except ConnectionRefusedError as e:
            logger.warning("%s: %s", e, target)
            sock.close()
        else:
            conns.append(service)


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

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--pattern', type=str, required=False, help="Ban a substring")
    group.add_argument('-i', '--input', type=str, required=False, help="File with patterns to be banned. Don't forget about transport encodings (e.g. url encoding)!")

    parser.add_argument('-s', '--str-encoding', type=str, required=False, default='utf8', help="Terminal/file/string encoding. Do not touch if in doubt (default set to utf8)")
    parser.add_argument('-e', '--encoding', type=str, required=False, default=None, help="Representation encoding: base64, hex, etc (from codecs.decode)")
    parser.add_argument('-c', '--chunk-size', type=int, required=False, default=1024, help="Chunk size for socket I/O")
    parser.add_argument('-m', '--max-len-of-pattern', type=int, required=False, default=None, help="Max length of pattern")

    parser.add_argument('-p', '--port', type=int, required=True, help="Port for wrapper to listen")

    parser.add_argument('-l', '--level', type=str, required=False, help="Log level")

    args = parser.parse_args()

    patterns = []

    logger = logging.getLogger(sys.argv[0])
    _ = logging.StreamHandler()
    _.setFormatter(logging.Formatter('[ %(asctime)s ][%(levelname)s]: %(message)s'))
    logger.addHandler(_)

    try:
        logger.setLevel(args.level.upper())
    except:
        logger.setLevel(logging.INFO)

    if args.input:
        with open(args.input, 'rb') as f:
            for line in f:
                patterns.append(line.strip())
    elif args.pattern:
        patterns.append(args.pattern.encode(args.str_encoding))

    if args.encoding:
        patterns = [decode(pattern, args.encoding) for pattern in patterns]
    
    if args.max_len_of_pattern is None:
        args.max_len_of_pattern = len(max(patterns, default='', key=len)) * 10

    args.patterns = patterns

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

    def evaler():
        cmd = sys.stdin.readline()
        code = compile(cmd, '<input>', 'single')
        eval(code, globals(), globals())

    loop.add_reader(sys.stdin.fileno(), evaler)

    loop.run_until_complete(master_socket_handler(loop, master_socket, args.chunk_size, args.max_len_of_pattern, patterns))
