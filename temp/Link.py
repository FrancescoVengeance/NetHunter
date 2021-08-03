from Element import Element


class Link:
    def __init__(self, _from, to, element: Element):
        self.to = to
        self._from = _from
        self.element = element

    def __eq__(self, other):
        return self.element == other.element

    def __hash__(self):
        return hash(self.element.hostname)