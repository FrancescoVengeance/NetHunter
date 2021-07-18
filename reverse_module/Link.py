import  Element


class Link:
    """
    A class modeling a link between two elements
    ----------
    port1 : str
        the port of the element owning this object
    port2 : str
        the port of the element connected
    element : Element
        the element with which is connected the one possessing this object
    """

    def __init__(self, port1, port2, element: Element):
        self.port1 = port1
        self.port2 = port2
        self.element = element

    def __eq__(self, other):
        return self.element == other.element

    def __hash__(self):
        return hash(self.element.ip)