"""Pure-Python MD4 digest algorithm implementation."""

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

# MD4 validation data

md4_test= [
      ('', 0x31d6cfe0d16ae931b73c59d7e0c089c0L),
      ("a",   0xbde52cb31de33e46245e05fbdbd6fb24L),
      ("abc",   0xa448017aaf21d8525fc10ae87aa6729dL),
      ("message digest",   0xd9130a8164549fe818874806e1c7014bL),
      ("abcdefghijklmnopqrstuvwxyz",   0xd79e1c308aa5bbcdeea8ed63df412da9L),
      ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
       0x043f8582f241db351ce627e153e7f0e4L),
      ("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      0xe33b4ddc9c38f2199c3e7b164fcc0536L),
     ]

from U32 import U32

class MD4Type:
    A = None
    B = None
    C = None
    D = None
    count, len1, len2 = None, None, None
    buf = []

    def __init__(self, data=""):


	self.A = U32(0x67452301L)
	self.B = U32(0xefcdab89L)
	self.C = U32(0x98badcfeL)
	self.D = U32(0x10325476L)
	self.count, self.len1, self.len2 = U32(0L), U32(0L), U32(0L)
	self.buf = [0x00] * 64
	self.update(data)

    def copy(self):

	dest = new()

	dest.len1 = self.len1
	dest.len2 = self.len2
	dest.A = self.A
	dest.B = self.B
	dest.C = self.C
	dest.D = self.D
	dest.count = self.count
	for i in range(self.count):
	    dest.buf[i] = self.buf[i]

	return dest

    def update(self, str):

	buf = []
	for i in str: buf.append(ord(i))
	ilen = U32(len(buf))
	#print (ilen)

	if (long(self.len1 + (ilen << 3)) < long(self.len1)):
	    self.len2 = self.len2 + U32(1)

	self.len1 = self.len1 + (ilen << 3)
	self.len2 = self.len2 + (ilen >> 29)
	# print int(self.len1), int(self.len2)
	#print (self.len1), (self.len2)

	L = U32(0)
	bufpos = 0
	while (long(ilen) > 0):
	    if (64 - long(self.count)) < long(ilen): L = U32(64 - long(self.count))
	    else: L = ilen
	    for i in range(int(L)): self.buf[i + int(self.count)] = buf[i + bufpos]
	    self.count = self.count + L
	    ilen = ilen - L
	    bufpos = bufpos + int(L)

	    #print self.count, L, ilen
	    if (long(self.count) == 64L):
		self.count = U32(0L)
		X = []
		i = 0
		for j in range(16):
		    X.append(U32(self.buf[i]) + (U32(self.buf[i+1]) << 8)  + \
		    (U32(self.buf[i+2]) << 16) + (U32(self.buf[i+3]) << 24))
		    i = i + 4

		A = self.A
		B = self.B
		C = self.C
		D = self.D

		A = f1(A,B,C,D, 0, 3, X)
		D = f1(D,A,B,C, 1, 7, X)
		C = f1(C,D,A,B, 2,11, X)
		B = f1(B,C,D,A, 3,19, X)
		A = f1(A,B,C,D, 4, 3, X)
		D = f1(D,A,B,C, 5, 7, X)
		C = f1(C,D,A,B, 6,11, X)
		B = f1(B,C,D,A, 7,19, X)
		A = f1(A,B,C,D, 8, 3, X)
		D = f1(D,A,B,C, 9, 7, X)
		C = f1(C,D,A,B,10,11, X)
		B = f1(B,C,D,A,11,19, X)
		A = f1(A,B,C,D,12, 3, X)
		D = f1(D,A,B,C,13, 7, X)
		C = f1(C,D,A,B,14,11, X)
		B = f1(B,C,D,A,15,19, X)

		A = f2(A,B,C,D, 0, 3, X)
		D = f2(D,A,B,C, 4, 5, X)
		C = f2(C,D,A,B, 8, 9, X)
		B = f2(B,C,D,A,12,13, X)
		A = f2(A,B,C,D, 1, 3, X)
		D = f2(D,A,B,C, 5, 5, X)
		C = f2(C,D,A,B, 9, 9, X)
		B = f2(B,C,D,A,13,13, X)
		A = f2(A,B,C,D, 2, 3, X)
		D = f2(D,A,B,C, 6, 5, X)
		C = f2(C,D,A,B,10, 9, X)
		B = f2(B,C,D,A,14,13, X)
		A = f2(A,B,C,D, 3, 3, X)
		D = f2(D,A,B,C, 7, 5, X)
		C = f2(C,D,A,B,11, 9, X)
		B = f2(B,C,D,A,15,13, X)

		A = f3(A,B,C,D, 0, 3, X)
		D = f3(D,A,B,C, 8, 9, X)
		C = f3(C,D,A,B, 4,11, X)
		B = f3(B,C,D,A,12,15, X)
		A = f3(A,B,C,D, 2, 3, X)
		D = f3(D,A,B,C,10, 9, X)
		C = f3(C,D,A,B, 6,11, X)
		B = f3(B,C,D,A,14,15, X)
		A = f3(A,B,C,D, 1, 3, X)
		D = f3(D,A,B,C, 9, 9, X)
		C = f3(C,D,A,B, 5,11, X)
		B = f3(B,C,D,A,13,15, X)
		A = f3(A,B,C,D, 3, 3, X)
		D = f3(D,A,B,C,11, 9, X)
		C = f3(C,D,A,B, 7,11, X)
		B = f3(B,C,D,A,15,15, X)

		self.A = self.A + A
		self.B = self.B + B
		self.C = self.C + C
		self.D = self.D + D
		#print self

    def digest(self):

	res = [0x00] * 16
	s = [0x00] * 8
	padding = [0x00] * 64
	padding[0] = 0x80
	padlen, oldlen1, oldlen2 = U32(0), U32(0), U32(0)

	temp = self.copy()

	oldlen1 = temp.len1
	oldlen2 = temp.len2
	if (56 <= long(self.count)): padlen = U32(56 - long(self.count) + 64)
	else: padlen = U32(56 - long(self.count))
	#print int(padlen)
	temp.update(int_array2str(padding[:int(padlen)]))
	#print temp

	s[0]= (oldlen1)        & U32(0xFF)
	s[1]=((oldlen1) >>  8) & U32(0xFF)
	s[2]=((oldlen1) >> 16) & U32(0xFF)
	s[3]=((oldlen1) >> 24) & U32(0xFF)
	s[4]= (oldlen2)        & U32(0xFF)
	s[5]=((oldlen2) >>  8) & U32(0xFF)
	s[6]=((oldlen2) >> 16) & U32(0xFF)
	s[7]=((oldlen2) >> 24) & U32(0xFF)
	temp.update(int_array2str(s))

	#print temp

	res[ 0]= temp.A        & U32(0xFF)
	res[ 1]=(temp.A >>  8) & U32(0xFF)
	res[ 2]=(temp.A >> 16) & U32(0xFF)
	res[ 3]=(temp.A >> 24) & U32(0xFF)
	res[ 4]= temp.B        & U32(0xFF)
	res[ 5]=(temp.B >>  8) & U32(0xFF)
	res[ 6]=(temp.B >> 16) & U32(0xFF)
	res[ 7]=(temp.B >> 24) & U32(0xFF)
	res[ 8]= temp.C        & U32(0xFF)
	res[ 9]=(temp.C >>  8) & U32(0xFF)
	res[10]=(temp.C >> 16) & U32(0xFF)
	res[11]=(temp.C >> 24) & U32(0xFF)
	res[12]= temp.D        & U32(0xFF)
	res[13]=(temp.D >>  8) & U32(0xFF)
	res[14]=(temp.D >> 16) & U32(0xFF)
	res[15]=(temp.D >> 24) & U32(0xFF)

	return int_array2str(res)

    def hexdigest(self):
	d=self.digest()
	return ''.join(map(lambda c: '%02x'%ord(c), d))

def F(x, y, z): return (((x) & (y)) | ((~x) & (z)))
def G(x, y, z): return (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
def H(x, y, z): return ((x) ^ (y) ^ (z))

def ROL(x, n): return (((x) << n) | ((x) >> (32-n)))

def f1(a, b, c, d, k, s, X): return ROL(a + F(b, c, d) + X[k], s)
def f2(a, b, c, d, k, s, X): return ROL(a + G(b, c, d) + X[k] + U32(0x5a827999L), s)
def f3(a, b, c, d, k, s, X): return ROL(a + H(b, c, d) + X[k] + U32(0x6ed9eba1L), s)

def int_array2str(array):
	str = ''
	for i in array:
	    str = str + chr(i)
	return str

def md4(data=''):
    return MD4Type(data)
def new(data=''):
    return MD4Type(data)
