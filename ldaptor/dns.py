"""DNS-related utilities."""

from socket import inet_aton, inet_ntoa

def aton_octets(ip):
    s=inet_aton(ip)
    octets=map(None, s)
    n = 0
    for o in octets:
        n=n<<8
        n+=ord(o)
    return n

def aton_numbits(num):
    n = 0
    while num>0:
        n>>=1
        n |= 2**31
        num-=1
    return n

def aton(ip):
    try:
        i=int(ip)
    except ValueError:
        return aton_octets(ip)
    else:
        return aton_numbits(i)

def ntoa(n):
    s=(
        chr((n>>24)&0xFF)
        + chr((n>>16)&0xFF)
        + chr((n>>8)&0xFF)
        + chr(n&0xFF)
       )
    ip=inet_ntoa(s)
    return ip

def netmaskToNumbits(netmask):
    bits = aton(netmask)
    i = 2**31
    n = 0
    while bits and i > 0:
        if (bits & i) == 0:
            if bits:
                raise RuntimeError("Invalid netmask: %s" % netmask)
        n += 1
        bits -= i
        i = i >> 1
    return n

def ptrSoaName(ip, netmask):
    """
    Convert an IP address and netmask to a CIDR delegation
    -style zone name.
    """
    net = aton(ip) & aton(netmask)

    nmBits = netmaskToNumbits(netmask)
    bytes, bits = divmod(nmBits, 8)
    octets = ntoa(net).split('.')
    octets.reverse()
    if not bits:
        octets = octets[-bytes:]
    else:
        partial = octets[-bytes-1]
        octets = octets[-bytes:]
        octets.insert(0, '%s/%d' % (partial, nmBits))

    return '.'.join(octets)+'.in-addr.arpa.'
