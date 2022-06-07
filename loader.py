'''
Loader slovnikov a pomocnych polii
'''
etherTypeDict = {}
IPV4ProtocolsDict = {}
IPV6ProtocolsDict = {}
LLCSAPsDict = {}
TCPProtocolsDict = {}
UDPProtocolsDict = {}

f = open("etherTypes.txt")
for etherType in f:
    line = etherType.strip().split(' ', 1)
    etherTypeDict[line[0]] = line[1]

f.close()
f = open("IPv4Protocols.txt")
for protocol in f:
    line = protocol.strip().split(' ', 1)
    IPV4ProtocolsDict[line[0]] = line[1]

f.close()
f = open("IPv6Protocols.txt")
for protocol in f:
    line = protocol.strip().split(' ', 1)
    IPV6ProtocolsDict[line[0]] = line[1]

f.close()
f = open("LLCSAPs.txt")
for sap in f:
    line = sap.strip().split(' ', 1)
    LLCSAPsDict[line[0]] = line[1]

f.close()
f = open("TCPProtocols.txt")
for tcpprotocol in f:
    line = tcpprotocol.strip().split(' ', 1)
    TCPProtocolsDict[line[0]] = line[1]

f.close()
f = open("UDPProtocols.txt")
for udpprotocol in f:
    line = udpprotocol.strip().split(' ', 1)
    UDPProtocolsDict[line[0]] = line[1]

f.close()
f = open("ICMPTypes.txt")

ICMPTypeDict = {}
ICMPCodeDict = {}
ICMPList = []

for icmp in f:
    line = icmp.strip().split(' ', 3)
    ICMPTypeDict[line[0]] = line[1]
    ICMPCodeDict.setdefault(line[0], {})[line[2]] = line[3]

f.close()
ICMPList.append(ICMPTypeDict)
ICMPList.append(ICMPCodeDict)

#print(ICMPList[1]["3"]["0"])
#print(ICMPTypeDict["0"])
#print(ICMPCodeDict["0"]["0"])


HTTP_LIST = []
HTTPS_LIST = []
TELNET_LIST = []
SSH_LIST = []
FTP_CONTROL_LIST = []
FTP_DATA_LIST = []
TFTP_LIST = []
ICMP_LIST = []
ARP_LIST = []

HTTP_LIST_PURE = []
HTTPS_LIST_PURE = []
TELNET_LIST_PURE = []
SSH_LIST_PURE = []
FTP_CONTROL_LIST_PURE = []
FTP_DATA_LIST_PURE = []
TFTP_LIST_PURE = []
ICMP_LIST_PURE = []
ARP_LIST_PURE = []


PIM_LIST = []
