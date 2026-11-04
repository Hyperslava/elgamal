"""Транспорт ничего не знает о криптографии. Для TCP заменить реализацию интерфейса."""
from abc import ABC, abstractmethod
from queue import Queue, Empty


class Transport(ABC):
    @abstractmethod
    def send(self, packet: bytes) -> None: ...

    @abstractmethod
    def receive_nowait(self) -> bytes | None: ...


class LocalTransport(Transport):
    def __init__(self):
        self.queue = Queue()

    def send(self, packet: bytes) -> None:
        self.queue.put(packet)

    def receive_nowait(self) -> bytes | None:
        try:
            return self.queue.get_nowait()
        except Empty:
            return None
