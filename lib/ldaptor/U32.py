"""Utility library for handling 32-bit unsigner integers."""

# http://www.geocities.com/rozmanov/python/

"""
From: "Dmitry Rozmanov" <dima@xenon.spb.ru>
To: "Tommi Virtanen" <tv@debian.org>
Subject: Re: About your md4.py

Hi.

Year, I am thinking of this, but could not find time for this. Thanks for
the link.

But why?

Consider it as a GPL for now if it is important.

Regards.

    ---Dmitry.

----- Original Message -----
From: "Tommi Virtanen" <tv@debian.org>
To: "Dmitry Rozmanov" <dima@xenon.spb.ru>
Sent: Tuesday, August 27, 2002 9:17 PM
Subject: About your md4.py


> Hi. Could you consider adding a license
> in your U32.py and md4.py files? Here's
> a quick reference:
>
> http://zooko.com/license_quick_ref.html
>
> --
> :(){ :|:&};:
"""

"""
From: "Dmitry Rozmanov" <dima@xenon.spb.ru>
To: "Tommi Virtanen" <tv@debian.org>
Subject: Re: About your md4.py

Ok. Let it be LGPL. Use libs, soon I will modify them and post to the site.

Regards.

    ---Dmitry.

----- Original Message -----
From: "Tommi Virtanen" <tv@debian.org>
To: "Dmitry Rozmanov" <dima@xenon.spb.ru>
Sent: Wednesday, August 28, 2002 9:21 AM
Subject: Re: About your md4.py


> On Wed, Aug 28, 2002 at 02:56:25AM +0400, Dmitry Rozmanov wrote:
> > Year, I am thinking of this, but could not find time for
> > this. Thanks for the link.
> >
> > But why?
> > 
> > Consider it as a GPL for now if it is important.
> 
> Please include that information in the files themselves;
> it would really help. Otherwise, all I have is this
> email to point to.
> 
> Oh, and please reconsider the actual license. For example,
> I have an LGPL'ed library I need md4 in. If you choose GPL,
> my library couldn't use your md4.py.
> 
> -- 
> :(){ :|:&};:
"""

C = 0x1000000000L

def norm(n):
    return n & 0xFFFFFFFFL


class U32:
    v = 0L

    def __init__(self, value = 0):
        self.v = C + norm(abs(long(value)))

    def set(self, value = 0):
        self.v = C + norm(abs(long(value)))

    def __repr__(self):
        return hex(norm(self.v))

    def __long__(self): return long(norm(self.v))
    def __int__(self): return int(norm(self.v))
    def __chr__(self): return chr(norm(self.v))

    def __add__(self, b):
        r = U32()
        r.v = C + norm(self.v + b.v)
        return r

    def __sub__(self, b):
        r = U32()
        if self.v < b.v:
            r.v = C + norm(0x100000000L - (b.v - self.v))
        else: r.v = C + norm(self.v - b.v)
        return r

    def __mul__(self, b):
        r = U32()
        r.v = C + norm(self.v * b.v)
        return r

    def __div__(self, b):
        r = U32()
        r.v = C + (norm(self.v) / norm(b.v))
        return r

    def __mod__(self, b):
        r = U32()
        r.v = C + (norm(self.v) % norm(b.v))
        return r

    def __neg__(self): return U32(self.v)
    def __pos__(self): return U32(self.v)
    def __abs__(self): return U32(self.v)

    def __invert__(self):
        r = U32()
        r.v = C + norm(~self.v)
        return r

    def __lshift__(self, b):
        r = U32()
        r.v = C + norm(self.v << b)
        return r

    def __rshift__(self, b):
        r = U32()
        r.v = C + (norm(self.v) >> b)
        return r

    def __and__(self, b):
        r = U32()
        r.v = C + norm(self.v & b.v)
        return r

    def __or__(self, b):
        r = U32()
        r.v = C + norm(self.v | b.v)
        return r

    def __xor__(self, b):
        r = U32()
        r.v = C + norm(self.v ^ b.v)
        return r

    def __not__(self):
        return U32(not norm(self.v))

    def truth(self):
        return norm(self.v)

    def __cmp__(self, b):
        if norm(self.v) > norm(b.v): return 1
        elif norm(self.v) < norm(b.v): return -1
        else: return 0

    def __nonzero__(self):
        return norm(self.v)
