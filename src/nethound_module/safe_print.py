from threading import RLock


class SafePrint:
    def __init__(self):
        self.lock: RLock = RLock()

    def print(self, string):
        with self.lock:
            print(string)