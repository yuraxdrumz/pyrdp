from StringIO import StringIO
from rdpy.core import der
from rdpy.pdu.rdp.cssp import TSRequestPDU


class CredSSPParser:
    def parseNegoData(self, construct):
        """
        :type construct: der.DERParser
        :return: list
        """
        sequence = construct.readSequence()
        tokens = []

        while len(sequence) > 0:
            token = sequence.readSequence().readConstruct().readOctetStream()
            tokens.append(token)

        return tokens

    def writeNegoData(self, writer, tokens):
        """
        :type writer: der.DERWriter
        :type tokens: list
        """
        sequence = writer.writeSequence()

        for token in tokens:
            sequence.writeSequence().writeConstruct().writeOctetStream(token)

    def parseTSRequest(self, stream):
        """
        Parse a TSRequest from a stream of DER-encoded data.
        :param stream: the stream of data.
        :type stream: StringIO
        :return: TSRequestPDU
        """
        root = der.DERParser(stream)
        tsRequestParser = root.readSequence()
        version = None
        tokens = None
        authInfo = None
        pubKeyAuth = None
        errorCode = None
        clientNonce = None

        while len(tsRequestParser) > 0:
            construct = tsRequestParser.readConstruct()
            if construct.index == 0:
                version = construct.readInteger()
            elif construct.index == 1:
                tokens = self.parseNegoData(construct)
            elif construct.index == 2:
                authInfo = construct.readOctetStream()
            elif construct.index == 3:
                pubKeyAuth = construct.readOctetStream()
            elif construct.index == 4:
                errorCode = construct.readInteger()
            elif construct.index == 5:
                clientNonce = construct.readOctetStream()

        return TSRequestPDU(version, tokens, authInfo, pubKeyAuth, errorCode, clientNonce)

    def writeTSRequest(self, pdu):
        """
        Write a TSRequest to bytes.
        :param pdu: the TSRequest object.
        :type pdu: TSRequestPDU
        :return: str
        """
        root = der.DERWriter()
        tsRequestSequence = root.writeSequence()

        if pdu.version:
            tsRequestSequence.writeConstruct(0).writeInteger(pdu.version)

        if pdu.negoTokens:
            self.writeNegoData(tsRequestSequence.writeConstruct(1), pdu.negoTokens)

        if pdu.authInfo:
            tsRequestSequence.writeConstruct(2).writeOctetStream(pdu.authInfo)

        if pdu.pubKeyAuth:
            tsRequestSequence.writeConstruct(3).writeOctetStream(pdu.pubKeyAuth)

        if pdu.errorCode:
            tsRequestSequence.writeConstruct(4).writeInteger(pdu.errorCode)

        if pdu.clientNonce:
            tsRequestSequence.writeConstruct(5).writeOctetStream(pdu.clientNonce)

        return root.getData()