from scapy.all import *
from binascii import hexlify
import os
import winsound #zvuk(už nie je implementovany)
import re #regexy

'''
Pomocna "kniznica", na pomocne funkcie a podobne
'''
def hexpackets(packets): #nahadzanie jednolivych hexdumpov do listu
    newpackets = []
    for packet in packets:
        newpackets.append(hexpacket(packet))
    return newpackets

def hexpacket(packet): #vytvorenie hex dump-u ramcov z pcap ramcov
    return (hexlify(raw(packet))).decode('ascii').upper()

def hexstr(str, start, len): #pomocna funkcia na vybratie casti stringu
    return str[start: start + bytes(len)]
    
def bytes(len): #2 znaky = 1B
    return int(len * 2)

def prettyHex(str):
    return ' '.join(str[i:i+2] for i in range(0,len(str), 2))

def printHex(packet, lineSize):
    i = 0
    output = ""
    for char in packet:
        if(i != 0 and i % 2 == 0):
            output += " "
            #print(" ", end = "")
        if(i != 0 and i % lineSize/2 == 0):
            output += "   "
            #print("   ", end = "")
        if (i != 0 and i % bytes(lineSize) == 0):
            output += "\n"
            #print("")
        output += char
        #print(char, end="")
        i +=1
    return output + "\n"

def hexIPAddress(hstr, offset, bitPart, partSize): #bitPart = 4 for IPv4, 16 for IPv6
    hstr = hexstr(hstr, offset, bitPart)
    nums = [hstr[i:i+bytes(partSize)] for i in range(0, len(hstr), bytes(partSize))]
    ipAddr = ""
    for num in nums:
        if (bitPart == 4):
            ipAddr += str(int(num, 16))
            ipAddr += "."
        elif(bitPart == 16):
            ipAddr += num
            ipAddr += ":"
    return ipAddr[:-1]

    #return str(int(nums[0], 16)) + "." + str(int(nums[1], 16)) + "." + str(int(nums[2], 16)) + "." + str(int(nums[3], 16))

def hexToBinaryStr(hexString):
    return bin(int(hexString, 16))[2:].zfill(len(hexString * 4))

def getflags(hexstr):
    return hexToBinaryStr(hexstr)[2:]

def getProtocolName(data, offset, length, fileName):
    protocols = open(fileName)
    for protocol in protocols:
        protocoltype, protocolTypeName = protocol.strip().split(' ', 1)
        if(int(hexstr(data, bytes(offset), length), 16) == int(protocoltype)):
             return protocolTypeName
    return None

def contains(element, array):
    for item in array:
        if(element == item):
            return True
    return False

def contains(element, array, pos):

    for item in array:
        if(element == item[pos]):
            return True
    return False

def getindex(element, array, pos):
    for i in range(0, len(array)):
        if(element == array[i][pos]):
            return i
    return -1

def fileName(path):
    return os.path.basename(path)

def stringToFile(fileName, output):
    if(os.path.exists(fileName)):
        open(fileName).close()

    f = open(fileName, "w")
    f.write(output)
    print("File " + fileName + " created!")

def play(songName):
    winsound.PlaySound(songName, winsound.SND_ASYNC | winsound.SND_FILENAME | winsound.SND_LOOP)

def hexi(str):
    return hex(int(str, 16))

def vartype(type):
    result = re.search('\'(.*)\'', str(type))
    type = result.group(1)
    if('.' in type):
        return type.split('.')[-1]
    else:
        return type

def listInList(sublist, list):
    count = 0
    for item in sublist:
        if(item in list):
            count += 1

    if(count == len(sublist)):
        return True
    return False
