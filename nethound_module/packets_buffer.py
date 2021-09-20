from threading import RLock, Condition
from pyshark.packet.packet import Packet


class PacketsBuffer:
    def __init__(self):
        self.buffer: [Packet] = []
        self.lock: RLock = RLock()
        self.empty_condition: Condition = Condition(self.lock)

    def pop(self, packet_type):
        with self.lock:
            while len(self.buffer) == 0:
                self.empty_condition.wait()

            self.empty_condition.notifyAll()
            print(f"Packet type {packet_type}")
            for packet in self.buffer:
                if packet.highest_layer.upper() == packet_type:
                    pkg_to_return = packet
                    self.buffer.remove(packet)
                    return pkg_to_return

    def put(self, packet) -> None:
        with self.lock:
            if len(self.buffer) <= 100:
                self.buffer.append(packet)
            else:
                self.buffer.clear()
