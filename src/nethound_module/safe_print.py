from threading import RLock


class SafePrint:
    def __init__(self):
        self.lock: RLock = RLock()

    def print(self, string, color=""):
        with self.lock:
            print(color + string)