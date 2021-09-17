from threading import RLock, Condition


class PacketsQueue:
    def __init__(self):
        self.buffer: list = []
        self.lock: RLock = RLock()
        self.empty_condition: Condition = Condition(self.lock)

    def pop(self, packet_type):
        with self.lock:
            while len(self.buffer) == 0:
                self.empty_condition.wait()

            self.empty_condition.notifyAll()
            if self.buffer[0].highest_layer.upper() == packet_type:
                print(f"Protocol {self.buffer[0].highest_layer.upper()}")
                return self.buffer.pop(0)

    def put(self, packet) -> None:
        with self.lock:
            self.buffer.append(packet)
