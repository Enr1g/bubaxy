import asyncio


class BushLoop(asyncio.SelectorEventLoop):
    # Patching event loop class
    def sock_recv_into(self, sock, buffer, n):
        if sock.gettimeout() != 0:
            raise ValueError("the socket must be non-blocking")

        fut = self.create_future()
        self._sock_recv_into(fut, False, sock, buffer, n)

        return fut

    def _sock_recv_into(self, fut, registered, sock, buffer, n):
        fd = sock.fileno()

        if registered:
            self.remove_reader(fd)

        if fut.cancelled():
            return
        try:
            nbytes = sock.recv_into(buffer, n)
        except (BlockingIOError, InterruptedError):
            self.add_reader(fd, self._sock_recv_into, fut, True, sock, buffer, n)
        except Exception as exc:
            fut.set_exception(exc)
        else:
            fut.set_result(nbytes)

    def fileio_readinto(self, fileio, buffer, n):
        fut = self.create_future()
        self._fileio_readinto(fut, False, fileio, buffer, n)

        return fut

    def _fileio_readinto(self, fut, registered, fileio, buffer, n):
        fd = fileio.fileno()

        if registered:
            self.remove_reader(fd)

        if fut.cancelled():
            return
        try:
            if registered:
                nbytes = fileio.readinto(buffer)
            else:
                raise BlockingIOError
        except (BlockingIOError, InterruptedError):
            self.add_reader(fd, self._fileio_readinto, fut, True, fileio, buffer, n)
        except Exception as exc:
            fut.set_exception(exc)
        else:
            fut.set_result(nbytes)