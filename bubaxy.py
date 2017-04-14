#!/usr/bin/env python3 -u
from codecs import decode
from bushloop import BushLoop
import subprocess
import traceback
import argparse
import asyncio
import logging
import select
import socket
import errno
import fcntl
import sys
import os


EPILOG = """Examples:
- Execute cat and ban substring 'shit' encoded in base64:
\t./wrapper.py --pattern 'c2hpdA==' -e base64 --cmd cat -p 31337
- Execute cat and ban substring 'GET / HTTP/0.9' encoded in hex:
\t./wrapper.py --pattern '474554202f20485454502f302e390a' -e hex --cmd cat -p 31337
- Wrap network service on port 8888 and manually set input cache size to 100:
\t./wrapper.py --pattern 'exploit' -b 100 --net 127.0.0.1:8888 -p 31337
"""

TASKS = []
# Or logging.getLogger(sys.argv[0]) every time? Nah, fuck it
logger = None


class Wrapper:
    """Wrapper for local / remote processes. All IO operations are non-blocking"""

    def __init__(self, service_type, target, loop):

        self.loop = loop

        if service_type == 'cmd':
            self._process = subprocess.Popen(
                target,
                shell=True,
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                bufsize=0
            )

            self.write_fno = self._process.stdout.fileno()

            # making it non-blocking
            flags = fcntl.fcntl(self.write_fno, fcntl.F_GETFL)
            fcntl.fcntl(self.write_fno, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            self.read_into = self._cmd_read_into
            self.write = self._cmd_write
            self.close = self._cmd_close
            self.recv_stopped = self._cmd_recv_stopped
            self.send_stopped = self._cmd_send_stopped

            self.fmt = (self._process.pid, self._process.args)

        elif service_type == 'net':
            self._sock = socket.socket()
            self._sock.connect(target)
            self._sock.setblocking(0)

            self.write_fno = self._sock.fileno()
            self.read_into = self._net_read_into
            self.write = self._net_write
            self.close = self._net_close
            self.recv_stopped = self._net_recv_stopped
            self.send_stopped = self._net_send_stopped

            self.fmt = []
            self.fmt.extend(self._sock.getsockname())
            self.fmt.extend(self._sock.getpeername())
            self.fmt = tuple(self.fmt)

        else:
            raise Exception("Unknown service type")

    def can_read(self):
        return select.select([self.write_fno], [], [], 0)[0] != []

    def _cmd_recv_stopped(self):
        self._process.stdin.close()

    def _cmd_send_stopped(self):
        self._process.stdout.close()

    def _cmd_close(self):
        self._process.terminate()

    async def _cmd_write(self, data):
        self._process.stdin.write(data)
        self._process.stdin.flush()

    async def _cmd_read_into(self, memory, chunk_size):
        nbytes = await self.loop.fileio_readinto(self._process.stdout, memory[:chunk_size], chunk_size)

        return nbytes

    def _net_recv_stopped(self):
        try:
            # TODO: QUESTIONABLE DECISION: Why SHUT_WR?
            self._sock.shutdown(socket.SHUT_WR)
        except OSError as e:
            # [Errno 57] Socket is not connected
            if e.errno != errno.ENOTCONN:
                raise e

    def _net_send_stopped(self):
        try:
            # TODO: QUESTIONABLE DECISION: Why SHUT_RD?
            self._sock.shutdown(socket.SHUT_RD)
        except OSError as e:
            # [Errno 57] Socket is not connected
            if e.errno != errno.ENOTCONN:
                raise e

    def _net_close(self):
        # asyncio surprisingly can fuck you w/o this step
        self.loop.remove_reader(self.write_fno)
        self._sock.close()

    async def _net_write(self, data):
        # TODO: QUESTIONABLE DECISION: Why sendall and not send?
        await self.loop.sock_sendall(self._sock, data)

    async def _net_read_into(self, memory, chunk_size):
        nbytes = await self.loop.sock_recv_into(self._sock, memory, chunk_size)

        return nbytes

    def __str__(self):
        if hasattr(self, "_sock"):
            return "<type=remote conn=(%s, %d) -> (%s, %d)>" % self.fmt
        else:
            return "<type=local [%d|%s]>" % self.fmt


class Process:

    def __init__(self, io_sock, service_type, target, loop, chunk_size=1024, max_len_of_pattern=100, patterns=None):
        self.process = Wrapper(service_type, target, loop)

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

        logger.info("%s was spawned" % self.process)

    async def disposer(self):
        # TODO: QUESTIONABLE DECISION: Is disposal guaranteed?
        await self.to_service_task
        await self.from_service_task
        self.dispose()

    async def to_service(self):
        try:
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
                    self.process.recv_stopped()
                    return

                # Processing
                self.mbuffer_in[:-nbytes] = self.mbuffer_in[nbytes:]

                # Looking for a bad pattern
                if self.storing and self.patterns:
                    for pattern in self.patterns:
                        # Actually, not from 0
                        if self.buffer_in.find(pattern, 0, self.chunk_size + self.max_len_of_pattern) > -1:
                            logger.info('Banned %s from %s' % (pattern, self.process))
                            return

                # Optimizing logging
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("%s received: %s", self.process,
                                 self.buffer_in[-self.chunk_size - nbytes: -self.chunk_size])

                try:
                    # send or sendall?
                    await self.process.write(self.mbuffer_in[-self.chunk_size - nbytes: -self.chunk_size])
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
        except Exception as e:
            logger.warning(e)
            traceback.print_stack()

    async def from_service(self):
        try:
            while True:
                # awaitable can throw an exception
                try:
                    nbytes = await self.process.read_into(self.mbuffer_out, self.chunk_size)
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
                    logger.debug("%s produced: %s", self.process, self.buffer_out[:nbytes])
                try:
                    await self.loop.sock_sendall(self.io_sock, self.mbuffer_out[:nbytes])
                except Exception as e:
                    # TODO: QUESTIONABLE DECISION: Can we do something more smart?
                    # we didn't manage to send all data
                    self.process.send_stopped()
        except Exception as e:
            logger.warning(e)
            traceback.print_stack()

    def dispose(self):
        logger.info('%s was disposed' % self.process)

        self.process.close()
        
        try:
            idx = TASKS.index(self)
            TASKS.pop(idx)
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
            process = Process(sock, service_type, target, loop, chunk_size, max_len_of_pattern, patterns)
        except ConnectionRefusedError as e:
            logger.warning(e)
            traceback.print_stack()
            sock.close()
        else:
            TASKS.append(process)


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
        print(eval(cmd))

    loop.add_reader(sys.stdin.fileno(), evaler)

    loop.run_until_complete(master_socket_handler(loop, master_socket, args.chunk_size, args.max_len_of_pattern, patterns))
