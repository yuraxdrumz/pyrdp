from rdpy.core import log

from rdpy.core.newlayer import Layer, LayerObserver
from rdpy.core.subject import ObservedBy
from rdpy.parser.cssp import CredSSPParser

class CredSSPObserver(LayerObserver):
    def onDataReceived(self, data):
        pass

@ObservedBy(CredSSPObserver)
class CredSSPLayer(Layer):
    def __init__(self):
        Layer.__init__(self)
        self.parser = CredSSPParser()
        self.destroyNext = False

    def recv(self, data):
        if self.observer:
            self.observer.onDataReceived(data)

    def sendData(self, data):
        self.previous.send(data)

    def sendPDU(self, pdu):
        self.destroyNext = True
        data = self.parser.writeTSRequest(pdu)
        log.info("DATA: %s" % data.encode("hex"))
        self.previous.send(data)