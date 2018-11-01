from StringIO import StringIO
from rdpy.core import der
from rdpy.pdu.rdp.cssp import TSRequestPDU


class CredSSPParser:
    def parseNegoData(self, parser):
        """
        :type parser: der.DERParser
        :return: list
        """
        sequence = parser.readSequence()
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

    def parseAuthInfo(self, parser):
        """
        :type parser: der.DERParser
        :return: TSCredentials
        """
        pass

    def parseTSRequest(self, stream):
        """
        Parse a TSRequest from a stream of DER-encoded data.
        :param stream: the stream of data.
        :type stream: StringIO
        :return: TSRequestPDU
        """
        root = der.DERParser(stream)
        tsRequestParser = root.readSequence()
        version = tsRequestParser.readConstruct().readInteger()
        tokens = self.parseNegoData(tsRequestParser.readConstruct())

        authInfo = None
        pubKeyAuth = None
        errorCode = None
        clientNonce = None

        if len(tsRequestParser) > 0:
            authInfo = tsRequestParser.readConstruct().readOctetStream()

        if len(tsRequestParser) > 0:
            pubKeyAuth = tsRequestParser.readConstruct().readOctetStream()

        if len(tsRequestParser) > 0:
            errorCode = tsRequestParser.readConstruct().readInteger()

        if len(tsRequestParser) > 0:
            clientNonce = tsRequestParser.readConstruct().readOctetStream()

            authInfo = tsRequestParser.readConstruct().readOctetStream()
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
        tsRequestSequence.writeConstruct().writeInteger(pdu.version)
        self.writeNegoData(tsRequestSequence.writeConstruct(), pdu.negoTokens)
        return root.getData()