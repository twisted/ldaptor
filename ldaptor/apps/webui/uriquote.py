import urllib

def uriQuote(uri):
    uri=str(uri)
    for c in '%;/?:@&+$':
	uri=uri.replace(c, '%%%02x'%ord(c))
    return uri

def uriUnquote(q):
    q=str(q)
    return urllib.unquote(q)
