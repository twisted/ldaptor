from twisted.internet import process, protocol, defer
from twisted.python import failure

class PwgenException(Exception):
    pass

class ReadPassword(protocol.ProcessProtocol):
    def __init__(self, deferred, count=1):
        self.deferred=deferred
        self.count=count
        self.stdout=''
        self.stderr=''

    def outReceived(self, data):
        self.stdout=self.stdout+data

    def errReceived(self, data):
        self.stderr=self.stderr+data

    def processEnded(self, reason):
        if self.stderr:
            self.deferred.errback(failure.Failure(
                PwgenException(reason, self.stderr)))
        elif self.stdout:
            lines=[x for x in self.stdout.split('\n') if x]
            if len(lines)!=self.count:
                self.deferred.errback(failure.Failure(
                    PwgenException(reason, 'Wrong number of lines received.')))
            self.deferred.callback(lines)
        else:
            self.deferred.errback(failure.Failure(PwgenException(reason, '')))

def generate(reactor, n=1):
    assert n>0
    d=defer.Deferred()
    proto=ReadPassword(d, n)
    process.Process(reactor, 'pwgen', ('pwgen', '-cn1', '-N', '%d'%n), {}, None, proto)
    return d

if __name__=='__main__':
    from twisted.internet import reactor
    import sys
    def say(passwords):
        for p in passwords:
            sys.stdout.write('%s\n' % p)
        return passwords

    def err(fail):
        fail.trap(PwgenException)
        sys.stderr.write('pwgen: %s\n' % fail.getErrorMessage())

    # Could get more passwords in one fork, but this stresses it more
    # on purpose.
    l=[]
    for i in range(5):
        d=generate(reactor, 5)
        d.addCallbacks(say, err)
        l.append(d)

    dl=defer.DeferredList(l)
    dl.addBoth(lambda dummy: reactor.stop())
    reactor.run()
