from classes import TFTP, FLAGS, Packet
from utils import vartype
from utils import bytes

'''
Pomocny subor na riesenie niektorych uloh
'''
def sourceIPResolver(packets): #riesenie ulohy 3a a 3b zaroven pomocou dictionaries
    allSourceIPDict = {}
    for packet in packets:
        if(packet.networkAccess.frameType == "Ethernet II" and packet.internet is not None and vartype(type(packet.internet)) == 'IPv4'):
            if(packet.internet.sourceIPAddress in allSourceIPDict.keys()):
                allSourceIPDict[packet.internet.sourceIPAddress] = allSourceIPDict[packet.internet.sourceIPAddress] + 1
            else:
                allSourceIPDict[packet.internet.sourceIPAddress] = 1

    maxSourceIP = max(allSourceIPDict, key = allSourceIPDict.get)
    output = "IP adresy vysielajúcich uzlov: \n"
    for sourceIP in allSourceIPDict.keys():
        output += sourceIP + "\n"
    output += "\n\nAdresa uzla s najväčším počtom odoslaných paketov: \n"
    output += maxSourceIP + "\t" + str(allSourceIPDict[maxSourceIP])

    return output

def isLookingFor(list, ip):
    if(len(list) == 0):
        return False
    for addr in list:
        if(addr.networkAccessLayer.specialProtocol.request and  addr.networkAccessLayer.specialProtocol.destinationIPAddress == ip):
            return True
    return False

def isInList(list, packet):
    for pair in list:
        if(pair.count(packet) > 0):
            return True
    return False

def ARPPairResolver(ARP_LIST): #vytvaranie arp parov z arp komunikacii
    arpCommuncationPairs = arpCommunications(ARP_LIST)
    ARP_COMM_LIST = []
    for arpCommunicationPair in arpCommuncationPairs:
        ARP_COMM = []
        openPair = False
        for i in range(0, len(arpCommunicationPair)):
            if(arpCommunicationPair[i].internet.request):
                ARP_COMM.append(arpCommunicationPair[i])
                openPair = True
            elif(arpCommunicationPair[i].internet.reply):
                ARP_COMM.append(arpCommunicationPair[i])
                if(openPair):
                    ARP_COMM_LIST.append((ARP_COMM, True))
                    ARP_COMM = []
                    openPair = False
        if(len(ARP_COMM) > 0):
            ARP_COMM_LIST.append((ARP_COMM, False))

    return ARP_COMM_LIST


def arpCommunications(ARP_LIST): #vytvaranie arp komunikacii
    ARP_COMMUNICATION_PAIRS = []
    for i in range(0, len(ARP_LIST)):
        COMM_LIST = []
        previous = ARP_LIST[i]
        if(not alreadyInList(previous, ARP_COMMUNICATION_PAIRS)):
            COMM_LIST.append(previous)
            for j in range(i + 1, len(ARP_LIST)):
                current = ARP_LIST[j]
                if (isPreviousIP(previous, current) or isSameIP(previous, current)):
                    COMM_LIST.append(current)

        if(len(COMM_LIST) > 0):
            ARP_COMMUNICATION_PAIRS.append(COMM_LIST)

    return ARP_COMMUNICATION_PAIRS


def isSame(previous, current):
    if (previous is None or current is None):
        return False
    if (previous.internet.sourceIPAddress == current.internet.sourceIPAddress and previous.internet.destinationIPAddress == current.internet.destinationIPAddress):
        if (previous.transport.sourcePort == current.transport.sourcePort and previous.transport.destinationPort == current.transport.destinationPort):
            return True

    return False

def isPrevious(previous, current):
    if(previous is None or current is None):
        return False
    if(previous.internet.sourceIPAddress == current.internet.destinationIPAddress and previous.internet.destinationIPAddress == current.internet.sourceIPAddress):
        if(previous.transport.sourcePort == current.transport.destinationPort and previous.transport.destinationPort == current.transport.sourcePort):
            return True

    return False

def isFromSameCommunication(compare, start):
    if(compare is None or start is None):
        return False
    if(compare.internet.sourceIPAddress == start.internet.sourceIPAddress or compare.internet.destinationIPAddress == start.internet.sourceIPAddress):
        if(compare.transport.sourcePort == start.transport.sourcePort or compare.transport.destinationPort == start.transport.sourcePort):
            return True
    return False

def TFTPResolver(TFTP_LIST, packets): #vytvorenie  pola tftp komunikacii
    communicationList = []
    for packet in TFTP_LIST:
        completeCommunication = []
        isTerminated = False
        if(packet.transport.destinationPort == 69 and (packet.application.READ() or packet.application.WRITE())):
            completeCommunication.append(packet)
            newServerPort = None
            previous = None
            for index in range(packet.position, len(packets)):
                if(vartype(type(packets[index].transport)) == 'UDP'):
                    if(newServerPort is None and isPreviousIP(packet, packets[index])): #first reply
                        newServerPort = packets[index].transport.sourcePort
                        packets[index].application = TFTP(packets[index].transport.getOffsetData())
                        packets[index].transport.nextProtocolName = 'TFTP'
                        completeCommunication.append(packets[index])
                        #print("Found new port")
                        previous = packets[index]
                    elif(newServerPort and (packets[index].transport.sourcePort == newServerPort or packets[index].transport.destinationPort == newServerPort)):
                        current = packets[index]
                        if(isFromSameCommunication(packets[index], packet)):
                            if (len(packets[index].transport.getOffsetData()) >= bytes(2) and int(packets[index].transport.getOffsetData()[:bytes(2)], 16) == 5 and len(packets[index].transport.getOffsetData()) <= bytes(516)): #aspom 4B aby som sa nepozeral na prazdne miesto AND ERROR 516-4=512
                                packets[index].transport.nextProtocolName = 'TFTP'
                                packets[index].application = TFTP(packets[index].transport.getOffsetData())
                                completeCommunication.append(packets[index])
                                isTerminated = True
                                print("Terminated at", packets[index].position)
                        if(isTerminated):
                            for j in range(packets[index].position, len(packets)):
                                if(vartype(type(packets[j].transport)) == 'UDP'):
                                    if (isPrevious(packets[index], packets[j])): #print(isPrevious(packets[index], packets[j])
                                        if (len(packets[j].transport.getOffsetData()) >= bytes(2) and (int(packets[j].transport.getOffsetData()[:bytes(2)], 16) == 3 or int(packets[j].transport.getOffsetData()[:bytes(2)], 16) == 4)):
                                            packets[j].transport.nextProtocolName = 'TFTP'
                                            packets[j].application = TFTP(packets[j].transport.getOffsetData())
                                            completeCommunication.append(packets[j]) #junk frames
                            break
                        if(isPrevious(previous, current)):
                            if(packets[index].transport is not None):
                                oldNextProtocol = packets[index].transport.nextProtocolName
                                if(packets[index].application is None):
                                    packets[index].transport.nextProtocolName = 'TFTP'
                                    packets[index].application = TFTP(packets[index].transport.getOffsetData())
                                if(packets[index].application.DATA()): #and packets[index].application.length() >= 512):
                                    completeCommunication.append(packets[index])
                                elif(packets[index].application.ACK())   :
                                    completeCommunication.append(packets[index])
                                else:
                                    packets[index].transport.nextProtocolName = oldNextProtocol
                                    packets[index].application = None
                        previous = current
        communicationList.append(completeCommunication)

    return communicationList

def endOfCommunication(list, indexList): #detekovanie konca TCP komunikacie
    index = indexList[-1] + 1
    previous = list[index-1]
    threshold = 4
    counter = 0

    while(counter < threshold and index < len(list)):
        current = list[index]
        if(current.transport.flag.SYN):
            break
        if(isPrevious(previous, current) or isSame(previous, current)):
            if(current.transport.flag.FIN or current.transport.flag.RST or current.transport.flag.ACK):
                indexList.append(index)
                counter += 1
        previous = current
        index += 1

    if(counter == 0):
        return False
    return True

def TCPCommunications(list): #vytvaranie pola kompletnych/nekompletnych komunikacii
    TCP_LIST = TCPCommunicationPairs(list)
    TCP_COMMUNICATION_LIST = []
    for tcpPair in TCP_LIST:
        index = 0
        while(index < len(tcpPair)):
            if(tcpPair[index].transport is not None and tcpPair[index].transport.flag.SYN and not tcpPair[index].transport.flag.ACK):
                INDEX_LIST = []
                flag_list = [(['SYN'], None), (['SYN', 'ACK'], 0), (['ACK'], 0)]
                indexList = communicationChecker(tcpPair, flag_list, index)
                if(len(indexList) == len(flag_list)):
                    INDEX_LIST.extend(indexList)
                    indexList = dataTransferResolver(tcpPair, INDEX_LIST[-1])
                    INDEX_LIST.extend(indexList)

                    completeComm = endOfCommunication(tcpPair, INDEX_LIST)
                    COMMUNICATION = []
                    for ix in INDEX_LIST:
                        COMMUNICATION.append(tcpPair[ix])
                    TCP_COMMUNICATION_LIST.append((COMMUNICATION, completeComm))
                    index = INDEX_LIST[-1]

            index += 1

    return TCP_COMMUNICATION_LIST


def dataTransferResolver(tcpList, index): #data transfer pri TCP
    INDEX_LIST = []
    previous = None
    if (len(tcpList) > 3):
        previous = tcpList[index]
    for i in range(index+1, len(tcpList)):
        current = tcpList[i]
        if (isSame(previous, current) or isPrevious(previous, current) and (previous.transport.flag.PSH or previous.transport.flag.ACK)):
            if (current.transport.flag.FIN or current.transport.flag.RST):
                break
            if (current.transport.flag.PSH or current.transport.flag.ACK):
                INDEX_LIST.append(i)
        previous = current
    return INDEX_LIST


FLAGS_LIST = []

for FLAG in vars(FLAGS):
    if(len(FLAG) == 3):
        FLAGS_LIST.append(FLAG)


def flagChecker(packet, flags): #kontrola flagov
    NOT_FLAGS = list(set(FLAGS_LIST) - set(flags))
    NOT_FLAGS.pop(NOT_FLAGS.index('URG'))
    arg = ""
    for flag in flags:
        arg += "packet.transport.flag." + flag + " and "

    arg = arg[:-4]
    '''if(not len(NOT_FLAGS)):
        arg = arg[:-4]
    else:
        arg += "not "
    for notflag in NOT_FLAGS:
        arg += "packet.transport.flag." + notflag + " and not "

    arg = arg[:-9]'''
    return eval(arg)

def suitableList(lists, previous):

    for list in lists:
        if(previous in list):
            return list

    return []

def communicationChecker(tcpPair, flag_list, index): #kontola komunikacie podla flagov
    flagCounter = 0
    INDEX_ARRAY = []
    previous = None
    start = 0
    if (index > 1):
        previous = tcpPair[index-1]
        start = index
    for i in range(start, len(tcpPair)):
        current = tcpPair[i]
        #print(vars(current.transport.flag))
        if (flagCounter < len(flag_list) and flagChecker(current, flag_list[flagCounter][0])):
            match flag_list[flagCounter][1]:
                case None:
                    flagCounter += 1
                    INDEX_ARRAY.append(i)
                case 0:
                    if (isPrevious(previous, current)):
                        flagCounter += 1
                        INDEX_ARRAY.append(i)
                case 1:
                    if (isSame(previous, current)):
                        flagCounter += 1
                        INDEX_ARRAY.append(i)
                case 2:
                    if (isPrevious(previous, current) or isSame(previous, current)):
                        flagCounter += 1
                        INDEX_ARRAY.append(i)
        else:
            break
        previous = current

    return INDEX_ARRAY

def isPreviousIP(previous, current):
    if(previous.internet is None or current.internet is None):
        return False
    if(previous.internet.sourceIPAddress == current.internet.destinationIPAddress and previous.internet.destinationIPAddress == current.internet.sourceIPAddress):
        return True
    return False

def isSameIP(previous, current):
    if(previous.internet is None or current.internet is None):
        return False
    if(previous.internet.sourceIPAddress == current.internet.sourceIPAddress and previous.internet.destinationIPAddress == current.internet.destinationIPAddress):
        return True
    return False

def alreadyInTupleList(previous, lists):
    for list in lists:
        if(previous in list):
            return True
    return False

def alreadyInList(previous, lists):
    for list in lists:
        if(previous in list):
            return True
    return False

def TCPCommunicationPairs(list): #TCP komunikacne pary podla IP a portov

    TCP_COMM_LIST = []
    for i in range(0, len(list)):
        COMM_LIST = []
        previous = list[i]
        if (not alreadyInTupleList(previous, TCP_COMM_LIST)):
            COMM_LIST.append(previous)
            # print("Printing comm for packet: ", previous.position)
            for j in range(i + 1, len(list)):
                current = list[j]
                if (isPrevious(previous, current) or isSame(previous, current)):
                    COMM_LIST.append(current)
                    # print("Commection detected at ", current.position)

        if (len(COMM_LIST) > 0):
            TCP_COMM_LIST.append(COMM_LIST)

    return TCP_COMM_LIST

def ICMPCommunicationPairs(list): #icmp komunikacne pary podla portov
    ICMP_COMM_LIST = []
    for i in range(0, len(list)):
        COMM_LIST = []
        previous = list[i]
        if(not alreadyInList(previous, ICMP_COMM_LIST)):
            COMM_LIST.append(previous)
            for j in range(i+1, len(list)):
                current = list[j]
                if(isPreviousIP(previous, current) or isSameIP(previous, current)):
                    COMM_LIST.append(current)

        if(len(COMM_LIST) > 0):
            ICMP_COMM_LIST.append(COMM_LIST)

    return ICMP_COMM_LIST



