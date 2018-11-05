from StringIO import StringIO

from rdpy.core.packing import Uint32LE
from rdpy.enum.ntlm import NTLMMessageType
from rdpy.exceptions import ParsingError


class NTLMParser:
    """
    NTLM token parser class for CredSSP.
    """

    def parse(self, data):
        stream = StringIO(data)
        signature = stream.read(8)
        type = Uint32LE.unpack(stream)

        if type == NTLMMessageType.NTLM_NEGOTIATE:
            return self.parseNegotiate(stream, signature)
        else:
            raise ParsingError("Invalid NTLM message type %d" % type)

    def parseNegotiate(self, stream, signature):
        negotiate = Uint32LE.unpack(stream)
        raise NotImplementedError("Negotiate message not implemented")