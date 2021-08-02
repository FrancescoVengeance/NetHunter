from threading import RLock

class ElementsManager:
    def __init__(self):
        self.toVisit = list()
        self.visited = list()
        self.elementsByIp = dict()
        self.elementsByMac = dict()
        self.elementsByHostname = dict()
        self.lock = RLock()

    def addToVisit(self, element):
        with self.lock:
            self.toVisit.append(element)

    def addToVisited(self, element):
        with self.lock:
            self.visited.append(element)

    def addElementByIp(self, ip: str, element):
        with self.lock:
            self.elementsByIp[ip] = element

    def addElementByMac(self, mac: str, element):
        with self.lock:
            self.elementsByMac[mac] = element

    def addElement(self, hostname: str, element):
        with self.lock:
            self.elementsByHostname[hostname] = element

    def popToVisit(self) -> str:
        with self.lock:
            return self.toVisit.pop(0)

    def getElementByIp(self, ip):
        with self.lock:
            return self.elementsByIp[ip]