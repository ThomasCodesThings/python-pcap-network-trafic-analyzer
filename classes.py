from loader import *
from utils import *

'''
Subor s definovanymi triedami
'''
class Template:
    data = None
    offset = 0
    nextProtocolName = None
    currentProtocolName = None

    def length(self):
        return int(len(self.data) / 2)

    def getOffsetData(self):
        return self.data[bytes(self.offset) : ]

class HTTP(Template):

    def print(self):
        return self.data + "\n"

    def __init__(self, data):
        self.data = data
        self.currentProtocolName = "HTTP"

class HTTPS(Template):

    def print(self):
        return self.data + "\n"

    def __init__(self, data):
        self.data = data
        self.currentProtocolName = "HTTPS"

class TELNET(Template):

    def print(self):
        return self.data + "\n"

    def __init__(self, data):
        self.data = data
        self.currentProtocolName = "TELNET"


class SSH(Template):

    def print(self):
        return self.data + "\n"

    def __init__(self, data):
        self.data = data
        self.currentProtocolName = "SSH"

class FTP_CONTROL(Template):

    def print(self):
        return self.data + "\n"

    def __init__(self, data):
        self.data = data
        self.currentProtocolName = "FTP_CONTROL"


class FTP_DATA(Template):

    def print(self):
        return self.data + "\n"

    def __init__(self, data):
        self.data = data
        self.currentProtocolName = "FTP_DATA"

class TFTP(Template):

    opcode = None
    #http://www.networksorcery.com/enp/protocol/tftp.htm
    def READ(self):
        if(self.opcode == 1):
            return True
        return False

    def WRITE(self):
        if(self.opcode == 2):
            return True
        return False

    def DATA(self):
        if(self.opcode == 3):
            return True
        return False

    def ACK(self):
        if(self.opcode == 4): #4 opcode for ACK
            return True
        return False

    def ERROR(self):
        if(self.opcode == 5):
            return True
        return False

    def print(self):
        opcodeName = ""
        match self.opcode:
            case 1:
                opcodeName = "READ"
            case 2:
                opcodeName = "WRITE"
            case 3:
                opcodeName = "DATA"
            case 4:
                opcodeName = "ACKnowledgement"
            case 5:
                opcodeName = "ERROR"
            case _:
                opcode = ""
        return "Opcode: " + str(self.opcode) + "(" + opcodeName + ")\n"

    def __init__(self, data):
        self.data = data
        self.opcode = int(self.data[:bytes(2)], 16)
        self.currentProtocolName = "TFTP"


class FLAGS:
    URG = False
    ACK = False
    PSH = False
    RST = False
    SYN = False
    FIN = False

    flags = []
    def isURG(self):
        if(self.flags[0] == "1"):
            return True
        return False

    def isACK(self):
        if (self.flags[1] == "1"):
            return True
        return False

    def isPSH(self):
        if (self.flags[2] == "1"):
            return True
        return False

    def isRST(self):
        if (self.flags[3] == "1"):
            return True
        return False

    def isSYN(self):
        if (self.flags[4] == "1"):
            return True
        return False

    def isFIN(self):
        if (self.flags[5] == "1"):
            return True
        return False

    def intflag(self):
        return list(map(int, self.flags))

    def __init__(self, flag):
        self.flags[:0] = flag
        self.URG = self.isURG()
        self.ACK = self.isACK()
        self.PSH = self.isPSH()
        self.RST = self.isRST()
        self.SYN = self.isSYN()
        self.FIN = self.isFIN()


class TCP(Template):
    sourcePort = 0
    destinationPort = 0
    seq = 0
    ack = 0
    flags = None
    windowSize = 0

    def findNextProtocol(self):
        if(int(hexstr(self.data, 0, 2), 16) <= int(hexstr(self.data, bytes(2), 2), 16)):
            if(str(int(hexstr(self.data, 0, 2), 16)) in TCPProtocolsDict.keys()):
                self.nextProtocolName = TCPProtocolsDict[str(int(hexstr(self.data, 0, 2), 16))]
                return
            else:
                self.nextProtocolName = None
        else:
            if (str(int(hexstr(self.data, bytes(2), 2), 16)) in TCPProtocolsDict.keys()):
                self.nextProtocolName = TCPProtocolsDict[str(int(hexstr(self.data, bytes(2), 2), 16))]
                return
            else:
                self.nextProtocolName = None
        if(self.nextProtocolName is None):
            self.nextProtocolName = "Undetected protocol: " + hexi(hexstr(self.data, 0, 2)).upper() + " | " + hexi(hexstr(self.data, bytes(2), 2)).upper()

    def print(self):
        flagList = "("
        for flag in vars(self.flag).items():
            if(flag[1]):
                flagList += flag[0] + ", "
        flagList = flagList[:-2]
        flagList += ")\n"

        return self.nextProtocolName + "\nzdrojový port: " + str(self.sourcePort) + "\ncieľový port: " + str(self.destinationPort) + "\n" + flagList

    def __init__(self, data):
        self.data = data
        self.offset = int(hexstr(self.data, bytes(12), 2), 16) * 4
        self.sourcePort = int(hexstr(self.data, 0, 2), 16)
        self.destinationPort = int(hexstr(self.data, bytes(2), 2), 16)
        self.findNextProtocol()
        self.seq = int(hexstr(self.data, 4, 4), 16)
        self.ack = int(hexstr(self.data, 8, 4), 16)
        self.flag = FLAGS(getflags(self.data[bytes(13):bytes(14)]))
        self.windowSize = int(self.data[bytes(14):bytes(16)], 16)
        self.currentProtocolName = "TCP"

class UDP(Template):
    sourcePort = 0
    destinationPort = 0

    def findNextProtocol(self):
        if (int(hexstr(self.data, 0, 2), 16) <= int(hexstr(self.data, bytes(2), 2), 16)):
            if (str(int(hexstr(self.data, 0, 2), 16)) in UDPProtocolsDict.keys()):
                self.nextProtocolName = UDPProtocolsDict[str(int(hexstr(self.data, 0, 2), 16))]
                return
            else:
                self.nextProtocolName = None
        else:
            if (str(int(hexstr(self.data, bytes(2), 2), 16)) in UDPProtocolsDict.keys()):
                self.nextProtocolName = UDPProtocolsDict[str(int(hexstr(self.data, bytes(2), 2), 16))]
                return
            else:
                self.nextProtocolName = None
        if (self.nextProtocolName is None):
            self.nextProtocolName = "Undetected protocol: " + hexi(hexstr(self.data, 0, 2)).upper() + " | " + hexi(hexstr(self.data, bytes(2), 2)).upper()

    def print(self):
        return self.nextProtocolName + "\nzdrojový port: " + str(self.sourcePort) + "\ncieľový port: " + str(self.destinationPort) + "\n"

    def __init__(self, data):
        self.data = data
        self.offset = 8
        self.sourcePort = int(hexstr(self.data, 0, 2), 16)
        self.destinationPort = int(hexstr(self.data, bytes(2), 2), 16)
        self.findNextProtocol()
        self.currentProtocolName = "UDP"

class ICMP(Template):
    type = None
    typeDescription = None
    code = None
    codeDescription = None

    def print(self):
        return self.typeDescription + "(type: " + self.type + "), " + self.codeDescription + "(code: " + self.code + ")" + "\n"  # "ICMP Message: " + self.typeDescription + "(type: "+ str(icmpType) + ")" + ".Reason: " + icmpFileCodeName + "(code: " + str(icmpCode) + ")"

    def details(self):
        self.type = str(int(hexstr(self.data, 0, 1), 16))
        self.code = str(int(hexstr(self.data, bytes(1), 1), 16))
        if(self.type in ICMPList[0].keys()):
            self.typeDescription = ICMPList[0][self.type]
            if('_' in self.typeDescription):
                self.typeDescription = self.typeDescription.replace('_', ' ')
            if(self.code in ICMPList[1][self.type].keys()):
                self.codeDescription = ICMPList[1][self.type][self.code]
            else:
                self.codeDescription = "Unknown code"
        else:
            self.typeDescription = "Unknown type"
            self.codeDescription = "Unknown code"


    def __init__(self, data):
        self.data = data
        self.details()
        self.currentProtocolName = "ICMP"


class IPv4(Template):
    sourceIPAddress = None
    destinationIPAddress = None

    def print(self):
        return "zdrojová IP adresa: " + self.sourceIPAddress + "\ncieľová IP adresa: " + self.destinationIPAddress + "\n" + self.nextProtocolName + "\n"

    def __init__(self, data):
        self.data = data
        self.offset = int(self.data[1], 16) * 4
        self.sourceIPAddress = hexIPAddress(self.data, bytes(12), 4, 1)
        self.destinationIPAddress = hexIPAddress(self.data, bytes(16), 4, 1)
        if(str(int(hexstr(self.data, bytes(9), 1), 16)) in IPV4ProtocolsDict.keys()):
            self.nextProtocolName = IPV4ProtocolsDict[str(int(hexstr(self.data, bytes(9), 1), 16))]
        else:
            self.nextProtocolName = "Undetected protocol:" + hexi(hexstr(self.data, bytes(9), 1)) #"Unknown protocol (" + str(int(hexstr(self.data, bytes(9), 1), 16)) + ")"
        self.currentProtocolName = "IPv4"

class ARP(Template):
    operation = None
    reply = False
    request = False
    sourceIPAddress = None
    sourceMACAddress = None
    destinationIPAddress = None
    destinationMACAddress = None
    answer = None
    IP = None
    def print(self):
        self.answer = "ARP-REQUEST" if (self.request == True and self.reply == False) else "ARP-REPLY"
        self.answer = "ARP-REPLY" if (self.reply == True and self.request == False) else "ARP-REQUEST"
        if(self.request):
            self.destinationMACAddress = "???"
            self.IP = self.destinationIPAddress
        else:
            self.IP = self.sourceIPAddress
            if(not " " in self.destinationMACAddress):
                self.destinationMACAddress = prettyHex(self.destinationMACAddress)
        return self.answer + ", IP adresa: " + self.IP + ", MAC adresa: " + self.destinationMACAddress + "\n" + "Zdrojová IP: " + self.sourceIPAddress + ", Cieľová IP: " + self.destinationIPAddress + "\n"

    def __init__(self, data):
        self.data = data
        self.operation = int(hexstr(self.data, bytes(6), 2),16)
        if(self.operation == 1):
            self.request = True
        elif(self.operation == 2):
            self.reply = True
        self.sourceMACAddress = hexstr(self.data, bytes(8), 6)
        self.sourceIPAddress = hexIPAddress(self.data, bytes(14), 4, 1)
        self.destinationMACAddress = hexstr(self.data, bytes(18), 6)
        self.destinationIPAddress = hexIPAddress(self.data, bytes(24), 4, 1)
        self.currentProtocolName = "ARP"

class NetworkAccessLayer(Template):
    sourceMACAddress = None
    destinationMACAddress = None
    frameType = None

    def print(self):
        return self.frameType + "\n" + "Zdrojová MAC adresa: " + prettyHex(self.sourceMACAddress) + "\n" + "Cieľová MAC adresa: " + prettyHex(self.destinationMACAddress) + "\n" + self.nextProtocolName + "\n"

    #Funkcia na zistenie typu ramca, uloha 1b
    def findFrameType(self):
        if(int(hexstr(self.data, bytes(12), 2), 16) >= 1536): # >= 1536 je Ethernet II(pole EtherType alebo Length)
            self.frameType = "Ethernet II"
            self.offset = 14
            if (hexstr(self.data, bytes(12), 2) in etherTypeDict.keys()):
                self.nextProtocolName = etherTypeDict[hexstr(self.data, bytes(12), 2)]
            else:
                self.nextProtocolName = "Undetected protocol:" + hexi(hexstr(self.data, bytes(12), 2))
            return
        elif(int(hexstr(self.data, bytes(12), 2), 16) <= 1500): # <= 1500 je LLC, LLC + SNAP, Novell RAW (pole "EtherType" alebo Length)

            if(hexstr(self.data, bytes(14), 2) == "FFFF"): # DSAP a SSAP su FF
                self.frameType = "Novell 802.3 RAW"
                self.nextProtocolName = "IPX"
                self.offset = 17
                return
            elif(hexstr(self.data, bytes(14), 2) == "AAAA"): # DSAP a SSAP su AA
                self.frameType = "802.3 LLC + SNAP"
                self.offset = 22
                if(hexstr(self.data, bytes(20), 2) in etherTypeDict.keys()): #dalej hladam protokol na 3 vrstve v poli etherType
                    self.nextProtocolName = etherTypeDict[hexstr(self.data, bytes(20), 2)]
                else:
                    self.nextProtocolName = "Undetected protocol:" + hexi(hexstr(self.data, bytes(20), 2))
                return
            else:
                self.frameType = "802.3 LLC" #inak ostatne co neviem blizsie indetifikovať je IEEE 802.3 LLC
                self.offset = 17
                if(hexstr(self.data, bytes(14), 1) in LLCSAPsDict.keys()): #Ak by som vedel rozpoznat protokol nad tym pomocou SAPov//and hexstr(self.data, bytes(15), 1) in LLCSAPsDict.keys()):
                    self.nextProtocolName = LLCSAPsDict[hexstr(self.data, bytes(14), 1)]
                else:
                    self.nextProtocolName = "Undetected protocol:" + hexi(hexstr(self.data, bytes(14), 2))
                return

        #self.frameType = None
        #self.nextProtocolName = None
        #self.offset = 0

    def __init__(self, data):
        self.data = data
        self.sourceMACAddress = hexstr(data, bytes(6), 6) #uloha 1c, druhych 6B
        self.destinationMACAddress = hexstr(data, 0, 6) #prvych 6B
        self.findFrameType()
        self.currentProtocolName = self.frameType


class PIM(Template):

    def __init__(self, data):
        self.data = data

    def print(self):
        return self.data + "\n"

class Packet(Template):

    position = 0
    pcapAPILength = 0
    mediaLength = 0
    networkAccess = None
    internet = None
    transport = None
    application = None

    def print(self):
        return "rámec " + str(self.position) + "\n" + "dĺžka rámca poskytnutá pcap API – " + str(self.pcapAPILength) + " B\n" + "dĺžka rámca prenášaného po médiu – " + str(self.mediaLength) + " B\n"

    def __init__(self, data, position):
        self.data = data
        self.position = position #poradove cislo ramca, uloha 1a
        self.pcapAPILength = int(len(self.data) / 2) #Uloha 1b, treba brat do uvahy(napr. '1F' tvori 1B(cize 8 bitov) -> 00011011) takze 2 char znaky su 1B(preto /2)
        '''
        Podobny princip ako je opisane o riadok vyssie,
        len s tym rozdielom ze 64B je minimalna velkost ramca ktory
        je mozny prenasat po 2 vrstve ISO/OSI modelu(1 vrstva TCP/IP)
        - Data Link(Network Access) + 4B tvori FCS(Frame Check Sequence)
        => takze kazdy ramec ktory ma menej ako 60B(64-4) sa k nemu pridaju 4B z FCS
        a zaokruhli sa na 64B. 
        Ak by mal ramec velkost vacsiu ako 60B tak sa len pridaju 4B k velkosti cize >60 + 4 B
        '''
        self.mediaLength = 64 if len(self.data) / 2 < 60 else int((len(self.data) / 2) + 4)
        self.networkAccess = NetworkAccessLayer(self.data)
        if(self.networkAccess.nextProtocolName is not None and self.networkAccess.frameType == "Ethernet II"):
            match self.networkAccess.nextProtocolName:
                case 'IPv4':
                    self.internet = IPv4(self.networkAccess.getOffsetData())
                case 'ARP':
                    self.internet = ARP(self.networkAccess.getOffsetData())
            if(self.internet is not None):
                if(vartype(type(self.internet)) == 'IPv4'):
                    match self.internet.nextProtocolName:
                        case 'TCP':
                            self.transport = TCP(self.internet.getOffsetData())
                        case 'UDP':
                            self.transport = UDP(self.internet.getOffsetData())
                        case 'ICMP':
                            self.transport = ICMP(self.internet.getOffsetData())
                        case 'PIM':
                            self.transport = PIM(self.internet.getOffsetData())
                        case _:
                            self.transport = None
                    if(self.transport is not None):
                        match self.transport.nextProtocolName:
                            case 'HTTP':
                                self.application = HTTP(self.transport.getOffsetData())
                            case 'HTTPS':
                                self.application = HTTPS(self.transport.getOffsetData())
                            case 'TELNET':
                                self.application = TELNET(self.transport.getOffsetData())
                            case 'SSH':
                                self.application = SSH(self.transport.getOffsetData())
                            case 'FTP-CONTROL':
                                self.application = FTP_CONTROL(self.transport.getOffsetData())
                            case 'FTP-DATA':
                                self.application = FTP_DATA(self.transport.getOffsetData())
                            case 'TFTP':
                                self.application = TFTP(self.transport.getOffsetData())
                            case _:
                                self.application = None



        #SORTING SYSTEM
        if(self.networkAccess is not None and self.networkAccess.frameType == "Ethernet II"):
            if(self.internet is not None):
                    match vartype(type(self.internet)):
                        case 'IPv4':
                            if(self.transport is not None):
                                match vartype(type(self.transport)):
                                    case 'TCP':
                                        if(self.application is not None):
                                            match vartype(type(self.application)):
                                                case 'HTTP':
                                                    HTTP_LIST.append(self)
                                                case 'HTTPS':
                                                    HTTPS_LIST.append(self)
                                                case 'TELNET':
                                                    TELNET_LIST.append(self)
                                                case 'SSH':
                                                    SSH_LIST.append(self)
                                                case 'FTP_CONTROL':
                                                    FTP_CONTROL_LIST.append(self)
                                                case 'FTP_DATA':
                                                    FTP_DATA_LIST.append(self)

                                    case 'UDP':
                                        if(self.application is not None):
                                            match vartype(type(self.application)):
                                                case 'TFTP':
                                                    TFTP_LIST.append(self)
                                    case 'ICMP':
                                        ICMP_LIST.append(self)
                                    case 'PIM':
                                        PIM_LIST.append(self)
                        case 'ARP':
                            ARP_LIST.append(self)




