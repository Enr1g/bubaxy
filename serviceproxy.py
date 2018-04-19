from servicewrapper import NetworkServiceWrapper, ExecutableServiceWrapper
from patterns import Patterns
import traceback
import asyncio
import logging
import socket
import errno

logger = logging.getLogger(__name__)


class ServiceProxy:
    conns = []
    chunk_size = 0
    max_len = 0
    patterns = None
    patterns_filename = None

    def __init__(self, io_sock, service_type, target, loop, chunk_size=1024):
        if service_type == 'net':
            self.service = NetworkServiceWrapper(target, loop)
        elif service_type == 'cmd':
            self.service = ExecutableServiceWrapper(target, loop)
        else:
            raise Exception("Unknown Service Type")

        ServiceProxy.chunk_size = chunk_size

        self.io_sock = io_sock
        self.io_fno = io_sock.fileno()
        self.io_sock.setblocking(0)

        self.loop = loop

        self.proxy_buffer_in = ProxyBuffer(ServiceProxy.chunk_size, ServiceProxy.patterns.max_len)
        self.total_bytes = 0

        self.buffer_in = None
        self.mbuffer_in = None
        self.buffer_out = bytearray(chunk_size)
        self.mbuffer_out = memoryview(self.buffer_out)

        self.to_service_task = asyncio.Task(self.to_service())
        self.from_service_task = asyncio.Task(self.from_service())

        self.loop.create_task(self.disposer())

        ServiceProxy.conns.append(self)

        logger.info("%s was spawned" % self.service)

    @staticmethod
    def set_chunk_size(chunk_size):
        ServiceProxy.chunk_size = chunk_size

    @staticmethod
    def update_patterns(filename=None):
        if filename:
            ServiceProxy.patterns_filename = filename

        ServiceProxy.patterns = Patterns(ServiceProxy.patterns_filename)

    async def disposer(self):
        # TODO: QUESTIONABLE DECISION: Is disposal guaranteed?
        try:
            await self.to_service_task
        except Exception as e:
            self.shutdown()
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
            self.buffer_in = self.proxy_buffer_in.get_buffer(ServiceProxy.patterns.max_len)
            self.mbuffer_in = self.proxy_buffer_in.get_memory(ServiceProxy.patterns.max_len)

            # awaitable can throw an exception
            try:
                nbytes = await self.loop.sock_recv_into(self.io_sock, self.mbuffer_in[-ServiceProxy.chunk_size:],
                                                        ServiceProxy.chunk_size)
            except Exception as e:
                nbytes = 0
                logger.warning(e)
                traceback.print_stack()

            self.total_bytes += nbytes

            # Got nothing, looks like eof
            if nbytes == 0:
                self.service.close_in()
                return

            # Processing
            self.mbuffer_in[:-nbytes] = self.mbuffer_in[nbytes:]

            pos = ServiceProxy.chunk_size + ServiceProxy.patterns.max_len - self.total_bytes
            needle = ServiceProxy.patterns.find(
                self.buffer_in,
                0 if pos < 0 else pos,
                ServiceProxy.chunk_size + ServiceProxy.patterns.max_len)

            if needle:
                logger.info('Banned %s from %s' % (needle, self.service))
                self.shutdown()
                return

            # Optimizing logging
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("%s received: %s", self.service,
                             self.buffer_in[-ServiceProxy.chunk_size - nbytes: -ServiceProxy.chunk_size])

            try:
                # send or sendall?
                await self.service.write(self.mbuffer_in[-ServiceProxy.chunk_size - nbytes: -ServiceProxy.chunk_size])
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
                nbytes = await self.service.read_into(self.mbuffer_out, ServiceProxy.chunk_size)
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

    def shutdown(self):
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

    def dispose(self):
        logger.info('%s was disposed' % self.service)

        self.service.close()

        try:
            idx = ServiceProxy.conns.index(self)
            ServiceProxy.conns.pop(idx)
        except Exception as e:
            logger.warning(e)
            traceback.print_stack()

        # asyncio surprisingly can fuck you w/o this step
        self.loop.remove_reader(self.io_fno)
        self.io_sock.close()


class ProxyBuffer:
    def __init__(self, chunk_size, max_pattern_len):
        self.chunk_size = chunk_size
        self.max_len = max_pattern_len
        self._buffer = bytearray(2 * self.chunk_size + self.max_len)
        self._memory = memoryview(self._buffer)

    def _update_max_len(self, max_pattern_len):
        to_rescue = min(self.max_len, max_pattern_len)
        self.max_len = max_pattern_len

        new_buffer = bytearray(2 * self.chunk_size + self.max_len)
        new_memory = memoryview(new_buffer)

        new_memory[- (2 * self.chunk_size + to_rescue):] = self._memory[- (2 * self.chunk_size + to_rescue):]

        self._buffer = new_buffer
        self._memory = new_memory

    def get_buffer(self, max_pattern_len):
        # supports only change of max_pattern_len at the moment
        if self.max_len != max_pattern_len:
            self._update_max_len(max_pattern_len)

        return self._buffer

    def get_memory(self, max_pattern_len):
        # supports only change of max_pattern_len at the moment
        if self.max_len != max_pattern_len:
            self._update_max_len(max_pattern_len)

        return self._memory
