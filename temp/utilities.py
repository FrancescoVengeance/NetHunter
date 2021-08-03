from threading import RLock
from Element import Element


class ElementsManager:
    def __init__(self):
        self.toVisit: list[Element] = list()
        self.visited: list[Element] = list()
        self.elementsByIp = dict()
        self.elementsByMac = dict()
        self.elementsByHostname = dict()
        self.lock = RLock()

    def addToVisit(self, element: Element):
        with self.lock:
            self.toVisit.append(element)

    def addToVisited(self, element: Element):
        with self.lock:
            self.visited.append(element)

    def addElementByIp(self, ip: str, element: Element):
        with self.lock:
            self.elementsByIp[ip] = element

    def addElementByMac(self, mac: str, element: Element):
        with self.lock:
            self.elementsByMac[mac] = element

    def addElement(self, hostname: str, element: Element):
        with self.lock:
            if hostname not in self.elementsByHostname.keys():
                self.elementsByHostname[hostname] = element

    def popToVisit(self) -> Element:
        with self.lock:
            return self.toVisit.pop(0)

    def getElementByIp(self, ip):
        with self.lock:
            return self.elementsByIp[ip]

    def getElementByHostname(self, hostname: str) -> Element:
        with self.lock:
            return self.elementsByHostname[hostname]


class EntryNotFoundException(Exception):
    """
    An exception raised if the entry is not present in the
    database of credentials
    """
    pass


class ElementException(Exception):
    """
    An exception raised if the element was instantiated with the wrong class
    """
    pass
