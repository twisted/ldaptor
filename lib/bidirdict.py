import UserDict

class BidirDict(UserDict.UserDict):
    def __init__(self, dict=None, **kwargs):
        self.reverse = {}
        UserDict.UserDict.__init__(self, dict)
        self.update(kwargs)

    def __setitem__(self, key, item):
        if self.has_key(key):
            del self.reverse[self[key]]
        UserDict.UserDict.__setitem__(self, key, item)
        assert not self.reverse.has_key(item)
        self.reverse[item] = key

    def __delitem__(self, key):
        del self.reverse[self[key]]
        UserDict.UserDict.__delitem__(self, key)

    def clear(self):
        UserDict.UserDict.clear()
        self.reverse.clear()

    def update(self, dict):
        for k, v in dict.items():
            self[k] = v

    def popitem(self):
        k,v = self.data.popitem()
        del self.reverse[v]
        return k,v
