from StringIO import StringIO

from rdpy.core import log

from rdpy.core.newlayer import Layer, LayerObserver
from rdpy.core.subject import ObservedBy
from rdpy.parser.cssp import CredSSPParser

class CredSSPObserver(LayerObserver):
    def onDataReceived(self, data):
        pass

    def onNTLMTokens(self, tokens):
        pass



@ObservedBy(CredSSPObserver)
class CredSSPLayer(Layer):
    def __init__(self):
        Layer.__init__(self)
        self.parser = CredSSPParser()
        self.destroyNext = False

    def recv(self, data):
        pdu = self.parser.parseTSRequest(StringIO(data))

        checkAttr = lambda name: log.info("    %s" % name) if getattr(pdu, name) else None

        log.info("Received TSRequest: {")
        checkAttr("version")
        checkAttr("negoTokens")
        checkAttr("authInfo")
        checkAttr("pubKeyAuth")
        checkAttr("errorCode")
        checkAttr("authInfo")
        checkAttr("clientNonce")
        log.info("}")

        if pdu.negoTokens:
            log.info("CredSSP negoTokens: %d tokens" % len(pdu.negoTokens))

        if pdu.errorCode:
            log.info("CredSSP error: 0x%lx" % pdu.errorCode)

        if self.observer:
            if pdu.negoTokens:
                for token in pdu.negoTokens:
                    if not token.startswith("NTLMSSP\x00"):
                        raise NotImplementedError("Only NTLM tokens are handled")

                self.observer.onNTLMTokens(pdu.negoTokens)

            self.observer.onDataReceived(data)

    def sendData(self, data):
        self.previous.send(data)

    def sendPDU(self, pdu):
        self.destroyNext = True
        data = self.parser.writeTSRequest(pdu)
        log.info("DATA: %s" % data.encode("hex"))
        self.previous.send(data)