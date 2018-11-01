from StringIO import StringIO

from rdpy.core import ber
from rdpy.core.packing import Uint8, Uint16BE, Uint32BE
from rdpy.exceptions import WritingError, ParsingError

def peekStream(stream, length):
    pos = stream.tell()
    data = stream.read(length)
    stream.seek(pos)
    return data



def isSequence(tag):
    return tag & 0x30 == 0x30

def isConstruct(tag):
    return tag & 0x20 != 0

def isInteger(tag):
    return tag & 0x3f == 0x02

def isOctetStream(tag):
    return tag & 0x3f == 0x04



def readTag(stream):
    return Uint8.unpack(stream)

def readLength(stream):
    return ber.readLength(stream)

def readHeader(stream):
    tag = readTag(stream)
    length = readLength(stream)
    return tag, length

def readSequence(stream):
    """
    Parse a DER sequence from a data stream.
    :param stream: the data stream.
    :type stream: StringIO.
    :return: the sequence data.
    """
    tag, length = readHeader(stream)

    if not isSequence(tag):
        raise ParsingError("Sequence tag expected, got 0x%02lx" % tag)

    return stream.read(length)

def readConstruct(stream):
    tag, length = readHeader(stream)

    if not isConstruct(tag):
        raise ParsingError("Construct expected, got primitive")

    return stream.read(length)

def readInteger(stream):
    tag, length = readHeader(stream)

    if not isInteger(tag):
        raise ParsingError("Integer tag expected, got 0x%02lx" % tag)

    if length == 1:
        return Uint8.unpack(peekStream(stream, 1))
    elif length == 2:
        return Uint16BE.unpack(peekStream(stream, 2))
    elif length == 3:
        integer1 = Uint8.unpack(peekStream(stream, 1))
        integer2 = Uint16BE.unpack(peekStream(stream, 2))
        return (integer1 << 16) + integer2
    elif length == 4:
        return Uint32BE.unpack(peekStream(stream, 4))

def readOctetStream(stream):
    tag, length = readHeader(stream)

    if not isOctetStream(tag):
        raise ParsingError("Octet Stream tag expected, got 0x%02lx" % tag)

    return stream.read(length)





def writeTag(tag, stream):
    Uint8.pack(tag, stream)

def writeLength(length, stream):
    stream.write(ber.writeLength(length))

def writeHeader(tag, length, stream):
    writeTag(tag, stream)
    writeLength(length, stream)

def writeSequence(data, stream):
    writeHeader(0x30, len(data), stream)
    stream.write(data)

def writeConstruct(data, stream):
    writeHeader(0x20, len(data), stream)
    stream.write(data)

def writeInteger(value, stream):
    stream.write(ber.writeInteger(value))

def writeOctetStream(data, stream):
    writeHeader(0x04, len(data), stream)
    stream.write(data)


class DERParser:
    def __init__(self, stream):
        """
        Create a new DERParser.
        :param stream: stream containing DER-encoded data.
        :type stream: StringIO
        """
        self.stream = stream

    def readSequence(self):
        """
        Read a sequence and create a new DERParser from the sequence data.
        :return: DERParser
        """
        stream = StringIO(readSequence(self.stream))
        return DERParser(stream)

    def readConstruct(self):
        """
        Read a construct and create a new DERParser from the construct data.
        :return: DERParser
        """
        stream = StringIO(readConstruct(self.stream))
        return DERParser(stream)

    def readInteger(self):
        """
        Read an integer from the stream.
        :return: int
        """
        return readInteger(self.stream)

    def readOctetStream(self):
        """
        Read an octet stream from the stream.
        :return: str
        """
        return readOctetStream(self.stream)

    def __len__(self):
        return self.stream.len - self.stream.pos

class DERWriter:
    def __init__(self, tag = None):
        """
        Create a new DERWriter.
        """
        self.tag = tag
        self.objects = []
        self.constructCount = 0

    def getData(self):
        """
        Get the DER-encoded data.
        :return: str
        """
        contents = "".join(o if isinstance(o, str) else o.getData() for o in self.objects)

        header = ""
        if self.tag is not None:
            stream = StringIO()
            writeHeader(self.tag, len(contents), stream)
            header = stream.getvalue()

        return header + contents

    def writeSequence(self):
        """
        Create a new sequence object.
        :return: DERWriter
        """
        sequence = DERWriter(0x30)
        self.objects.append(sequence)
        return sequence

    def writeConstruct(self):
        """
        Create a new construct object.
        :return: DERWriter
        """
        construct = DERWriter(0xa0 | self.constructCount)
        self.constructCount += 1
        self.objects.append(construct)
        return construct

    def writeInteger(self, value):
        """
        Encode an integer.
        :type value: int
        """
        stream = StringIO()
        writeInteger(value, stream)
        self.objects.append(stream.getvalue())

    def writeOctetStream(self, data):
        """
        Encode an octet stream.
        :type data: str
        """
        stream = StringIO()
        writeOctetStream(data, stream)
        self.objects.append(stream.getvalue())

