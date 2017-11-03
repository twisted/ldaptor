# -*- python -*-
#
# GSSAPI SASL Code for LDAP Auth
#
# This implements the RFC 4752 SASL Mechanism GSSAPI for ldaptor
#
# (c) 2016 CONTACT SOFTWARE GmbH (www.contact-software.com)
#
# MIT License.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

import sys
import base64
import struct

if sys.platform == 'win32':
    import kerberos_sspi as kerberos
else:
    import kerberos

__all__ = [
    'SASL_GSSAPIClientContext',
    'SASL_GSSAPIServerContext',
]


# RFC 4752 Sect. 3
SASL_MECHANISM = 'GSSAPI'


class SASL_GSSAPIClientContext(object):

    def __init__(self, service, host):
        spn = "%s@%s" % (service, host)
        self.client = None
        self.response = ""
        self.cres = kerberos.AUTH_GSS_CONTINUE
        self.ctx = None

        flags = (kerberos.GSS_C_CONF_FLAG
                 | kerberos.GSS_C_INTEG_FLAG
                 | kerberos.GSS_C_REPLAY_FLAG
                 | kerberos.GSS_C_SEQUENCE_FLAG)

        errc, self.client = kerberos.authGSSClientInit(spn, gssflags=flags)

        self._round = 0

    def send(self, token_in):
        if not self.ctx:
            self.ctx = self._coro()
            # Move to first waiting yield
            self.ctx.send(None)
        return self.ctx.send(token_in)

    def __del__(self):
        # TODO: Find a nicer way to trigger cleanup
        self.ctx = None
        client = self.client
        self.client = None
        if client:
            kerberos.authGSSClientClean(client)

    def start(self):
        ctx = self._coro()
        # Move to first waiting yield
        ctx.send(None)
        return ctx

    def _handle_sasl_gssapi(self, token_in):
        if sys.platform == "win32":
            return self._handle_sasl_gssapi_win32(token_in)
        else:
            return self._handle_sasl_gssapi_unix(token_in)

    def _handle_sasl_gssapi_win32(self, token_in):
        # TODO: Simplify if kerberos_sspi gets fixed and authGSSClientUnwrap()
        #       works as it should.
        # (https://github.com/may-day/kerberos-sspi/pull/3)
        code = kerberos.authGSSClientUnwrap(
            self.ctx, base64.encodestring(token_in))
        if code == -1:
            raise RuntimeError("SASL GSSAPI Auth failed")

        data = kerberos.authGSSClientResponse(self.ctx)
        data = self._process_security_options(data)
        import sspicon
        import win32security
        ca = self.ctx['csa']
        context = self.ctx
        pkg_size_info = ca.ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_SIZES)
        trailersize = pkg_size_info['SecurityTrailer']
        blocksize = pkg_size_info['BlockSize']

        encbuf = win32security.PySecBufferDescType()
        encbuf.append(win32security.PySecBufferType(trailersize, sspicon.SECBUFFER_TOKEN))
        encbuf.append(win32security.PySecBufferType(len(data), sspicon.SECBUFFER_DATA))
        encbuf.append(win32security.PySecBufferType(blocksize, sspicon.SECBUFFER_PADDING))
        encbuf[1].Buffer = data
        ca.ctxt.EncryptMessage(0, encbuf, ca._get_next_seq_num())

        context["response"] = encbuf[0].Buffer+encbuf[1].Buffer+encbuf[2].Buffer
        self.response = kerberos.authGSSClientResponse(self.ctx)

    def _handle_sasl_gssapi_unix(self, token_in):
        # TODO: Probably needs a fix similar to kerberos_sspi
        pass

    def _process_security_options(self, data, user=None):
        """
        Handle the security layer settings
        """
        conf_and_size = data[:struct.calcsize("!L")]  # network unsigned long
        size = struct.unpack("!L", conf_and_size)[0] & 0x00ffffff
        conf = struct.unpack("B", conf_and_size[0])[0]  # B .. unsigned char

        # FIXME: Debug prints...
        print "N" if conf & kerberos.GSS_AUTH_P_NONE else "-"
        print "I" if conf & kerberos.GSS_AUTH_P_INTEGRITY else "-"
        print "P" if conf & kerberos.GSS_AUTH_P_PRIVACY else "-"
        print "Maximum GSS token size is %d" % size

        # Tell the truth, we do not handle any security layer
        # (aka GSS_AUTH_P_NONE). RFC 4752 demands that the
        # max client message size is zero in this case.
        max_size_client_message = 0
        security_layer = kerberos.GSS_AUTH_P_NONE
        data = struct.pack("!L", security_layer << 24 +
                           (max_size_client_message & 0x00ffffff))
        if user:
            data = data + user.encode("utf-8")
        return data

    def _coro(self):
        """
        Statemachine for the SASL progress
        """
        token_in = yield
        while self.cres == kerberos.AUTH_GSS_CONTINUE:
            self.cres = kerberos.authGSSClientStep(
                self.ctx,
                base64.encodestring(token_in) if token_in is not None else None
            )
            if self.cres == -1:
                break
            self.response = kerberos.authGSSClientResponse(self.ctx)
            self._round += 1
            token_in = yield (SASL_MECHANISM, base64.decodestring(self.response))
        if self.cres == kerberos.AUTH_GSS_COMPLETE:
            token_in = yield (SASL_MECHANISM, base64.decodestring(self.response))
            self._handle_sasl_gssapi(token_in)
            yield (SASL_MECHANISM, base64.decodestring(self.response))
        else:
            raise RuntimeError("Unexpected extra token. Auth Failed")


class SASL_GSSAPIServerContext(object):
    def __init__(self):
        pass
