import subprocess
import socket
import fcntl
import errno
import os


class ServiceWrapper:
    """Wrapper for local / remote processes. All IO operations are non-blocking"""

    def __init__(self, target):
        pass

    def close_in(self):
        raise NotImplementedError

    def close_out(self):
        raise NotImplementedError

    def close_in_out(self):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    async def write(self, data):
        raise NotImplementedError

    async def read_into(self, memory, chunk_size):
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError


class ExecutableServiceWrapper(ServiceWrapper):
    def __init__(self, target):
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

        self.fmt = (self._process.pid, self._process.args)

    def __str__(self):
        return "<type=local [%d|%s]>" % self.fmt

    def close_in(self):
        self._process.stdin.close()

    def close_out(self):
        self._process.stdout.close()

    def close_in_out(self):
        self._process.stdin.close()
        self._process.stdout.close()

    def close(self):
        self._process.terminate()

    async def write(self, data):
        self._process.stdin.write(data)
        self._process.stdin.flush()

    async def read_into(self, memory, chunk_size):
        nbytes = await self.loop.fileio_readinto(self._process.stdout, memory[:chunk_size], chunk_size)

        return nbytes


class NetworkServiceWrapper(ServiceWrapper):
    def __init__(self, target, loop):
        self.loop = loop

        self._sock = socket.socket()
        self._sock.connect(target)
        self._sock.setblocking(0)

        self.write_fno = self._sock.fileno()

        self.fmt = []
        self.fmt.extend(self._sock.getsockname())
        self.fmt.extend(self._sock.getpeername())
        self.fmt = tuple(self.fmt)

    def __str__(self):
        return "<type=remote conn=(%s, %d) -> (%s, %d)>" % self.fmt

    def close_in(self):
        try:
            self._sock.shutdown(socket.SHUT_WR)
        except OSError as e:
            # [Errno 57] Socket is not connected
            if e.errno != errno.ENOTCONN:
                raise e

    def close_out(self):
        try:
            self._sock.shutdown(socket.SHUT_RD)
        except OSError as e:
            # [Errno 57] Socket is not connected
            if e.errno != errno.ENOTCONN:
                raise e

    def close_in_out(self):
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            # [Errno 57] Socket is not connected
            if e.errno != errno.ENOTCONN:
                raise e

    def close(self):
        # asyncio surprisingly can fuck you w/o this step
        self.loop.remove_reader(self.write_fno)
        self._sock.close()

    async def write(self, data):
        # TODO: QUESTIONABLE DECISION: Why sendall and not send?
        await self.loop.sock_sendall(self._sock, data)

    async def read_into(self, memory, chunk_size):
        nbytes = await self.loop.sock_recv_into(self._sock, memory, chunk_size)

        return nbytes
