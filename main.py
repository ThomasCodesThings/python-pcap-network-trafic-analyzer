from tkinter import * #tkinter kniznica na GUI rozhranie
import tkinter.filedialog #rozhranie pop up okna na otvorenie suboru
from classes import *
from communications import *

isLoaded = False
packets = []

root = None
exists = False
textBox = None
VERSION = "2.0"
TITLE_NAME = "Network Traffic Analyzer v" + VERSION
FILE_NAME = None

MAX = 20
BLANK_PACKET = "...............\n"

def clearTextBox(): #premazanie textoveho boxu
    global textBox
    if (textBox is not None):
        textBox.delete(1.0, END)
        textBox.pack_forget()
        textBox = None
        print("Deleted Text Box")
    if(textBox is None):
        return True
    return False

def createTextBox(): #vytvorenie textoveho boxu
    global textBox
    if(textBox is None):
        global root
        textBox = Text(root, height=35, width=75, yscrollcommand=True)
        textBox.pack(side=tkinter.TOP)
        print("Created Text Box")
    if(textBox is not None):
        return True
    return False

def popUP(text):
    popUpWindow = Tk()
    popUpWindow.title("Loaded")
    Label(popUpWindow, text = text).pack(side = tkinter.TOP)
    okButton = Button(popUpWindow, text = "OK", command = popUpWindow.destroy).pack(side = tkinter.TOP)

def show(root, file):
    root.title(TITLE_NAME + " [" + file + "]")
    isChecked = []
    for i in range(0, 10):
        isChecked.append(BooleanVar())
    frame = Frame(root)
    global exists
    if(not exists):
        firstToThreeTaskCheckBox = Checkbutton(frame, text="Create file", var=isChecked[0])
        firstToThreeTaskButton = Button(frame, text="Task 1-3", command=lambda: firstToThreeTask(isChecked[0].get()))
        fourthACheckBox = Checkbutton(frame, text = "Create file", var = isChecked[1])
        fourthAButton = Button(frame, text="Task 4 a)", command=lambda: fourATask(isChecked[1].get()))
        fourthBCheckBox = Checkbutton(frame, text="Create file", var=isChecked[2])
        fourthBButton = Button(frame, text="Task 4 b)", command=lambda: fourBTask(isChecked[2].get()))
        fourthCCheckBox = Checkbutton(frame, text="Create file", var=isChecked[3])
        fourthCButton = Button(frame, text="Task 4 c)", command=lambda: fourCTask(isChecked[3].get()))
        fourthDCheckBox = Checkbutton(frame, text="Create file", var=isChecked[4])
        fourthDButton = Button(frame, text="Task 4 d)", command=lambda: fourDTask(isChecked[4].get()))
        fourthECheckBox = Checkbutton(frame, text="Create file", var=isChecked[5])
        fourthEButton = Button(frame, text="Task 4 e)", command=lambda: fourETask(isChecked[5].get()))
        fourthFCheckBox = Checkbutton(frame, text="Create file", var=isChecked[6])
        fourthFButton = Button(frame, text="Task 4 f)", command=lambda: fourFTask(isChecked[6].get()))
        fourthGCheckBox = Checkbutton(frame, text="Create file", var=isChecked[7])
        fourthGButton = Button(frame, text="Task 4 g)", command=lambda: fourGTask(isChecked[7].get()))
        fourthHCheckBox = Checkbutton(frame, text="Create file", var=isChecked[8])
        fourthHButton = Button(frame, text="Task 4 h)", command=lambda: fourHTask(isChecked[8].get()))
        fourthICheckBox = Checkbutton(frame, text="Create file", var=isChecked[9])
        fourthIButton = Button(frame, text="Task 4 i)", command=lambda: fourITask(isChecked[9].get()))
        firstToThreeTaskButton.grid(column=0, row=1)
        firstToThreeTaskCheckBox.grid(column = 1, row = 1)
        fourthAButton.grid(column=0, row=2)
        fourthACheckBox.grid(column=1, row=2)
        fourthBButton.grid(column=0, row=3)
        fourthBCheckBox.grid(column = 1, row = 3)
        fourthCButton.grid(column=0, row=4)
        fourthCCheckBox.grid(column=1, row=4)
        fourthDButton.grid(column=0, row=5)
        fourthDCheckBox.grid(column=1, row=5)
        fourthEButton.grid(column=0, row=6)
        fourthECheckBox.grid(column=1, row=6)
        fourthFButton.grid(column=0, row=7)
        fourthFCheckBox.grid(column=1, row=7)
        fourthGButton.grid(column=0, row=8)
        fourthGCheckBox.grid(column=1, row=8)
        fourthHCheckBox.grid(column=1, row=9)
        fourthHButton.grid(column=0, row=9)
        fourthICheckBox.grid(column=1, row=10)
        fourthIButton.grid(column=0, row=10)
        frame.pack(side = tkinter.TOP)
        exists = True
    else:
        frame.pack_forget()


def firstToThreeTask(isChecked): #uloha 1 az 3
    if(isLoaded):
        output = ""
        for packet in packets:
            output += packet.print() + packet.networkAccess.print()
            if(packet.internet is not None):
                output += packet.internet.print()
            if(packet.transport is not None):
                output += packet.transport.print()
            output += printHex(packet.data, 16) + "\n\n"

        output += sourceIPResolver(packets)
        if (clearTextBox()):
            if (createTextBox()):
                if (isChecked):
                    stringToFile("1-3_output.txt", output)
                    textBox.insert(INSERT, "Output written to file " + "1-3_output.txt")
                else:
                    textBox.insert(INSERT, output)

        textBox.config(state=DISABLED)

def fourATask(isChecked):
    if (isLoaded):
        output = ""
        if(not len(HTTP_LIST_PURE)):
            output = "No HTTP packets found!"
        else:
            output += "Kompletné komunikácie:\n\n"
            counter = 0
            for i in range(0, len(HTTP_LIST)):
                if(HTTP_LIST[i][1]):
                    counter += 1
                    output += "Komunikácia č." + str(counter) + "\n"
                    for index in range(0, len(HTTP_LIST[i][0])):
                        packet = HTTP_LIST[i][0][index]
                        if(index < int(MAX/2) or index >= int(len(HTTP_LIST[i][0]) - (MAX/2))):
                            output += packet.print() + packet.networkAccess.print()
                            if (packet.internet is not None):
                                output += packet.internet.print()
                            if (packet.transport is not None):
                                output += packet.transport.print()
                            output += printHex(packet.data, 16) + "\n\n"
                        else:
                            output += BLANK_PACKET
                    break

            counter = 0
            output += "Nekompletné komunikácie:\n\n"
            for i in range(0, len(HTTP_LIST)):
                if (not HTTP_LIST[i][1]):
                    counter += 1
                    output += "Komunikácia č." + str(counter) + "\n"
                    for index in range(0, len(HTTP_LIST[i][0])):
                        packet = HTTP_LIST[i][0][index]
                        if (index < int(MAX / 2) or index >= int(len(HTTP_LIST[i][0]) - (MAX / 2))):
                            output += packet.print() + packet.networkAccess.print()
                            if (packet.internet is not None):
                                output += packet.internet.print()
                            if (packet.transport is not None):
                                output += packet.transport.print()
                            output += printHex(packet.data, 16) + "\n\n"
                        else:
                            output += BLANK_PACKET
                    break

        if (clearTextBox()):
            if (createTextBox()):
                if (isChecked):
                    stringToFile("4a_output.txt", output)
                    textBox.insert(INSERT, "Output written to file " + "4a_output.txt")
                else:
                    textBox.insert(INSERT, output)

        textBox.config(state=DISABLED)

def fourBTask(isChecked):
    if (isLoaded):
        output = ""
        if (not len(HTTPS_LIST_PURE)):
            output = "No HTTPS packets found!"
        else:
            output += "Kompletné komunikácie:\n\n"
            counter = 0
            for i in range(0, len(HTTPS_LIST)):
                if (HTTPS_LIST[i][1]):
                    counter += 1
                    output += "Komunikácia č." + str(counter) + "\n"
                    for index in range(0, len(HTTPS_LIST[i][0])):
                        packet = [index][i][0][index]
                        if (index < int(MAX / 2) or index >= int(len(HTTPS_LIST[i][0]) - (MAX / 2))):
                            output += packet.print() + packet.networkAccess.print()
                            if (packet.internet is not None):
                                output += packet.internet.print()
                            if (packet.transport is not None):
                                output += packet.transport.print()
                            output += printHex(packet.data, 16) + "\n\n"
                        else:
                            output += BLANK_PACKET
                    break

            counter = 0
            output += "Nekompletné komunikácie:\n\n"
            for i in range(0, len(HTTPS_LIST)):
                if (not HTTPS_LIST[i][1]):
                    counter += 1
                    output += "Komunikácia č." + str(counter) + "\n"
                    for index in range(0, len(HTTPS_LIST[i][0])):
                        packet = HTTPS_LIST[i][0][index]
                        if (index < int(MAX / 2) or index >= int(len(HTTPS_LIST[i][0]) - (MAX / 2))):
                            output += packet.print() + packet.networkAccess.print()
                            if (packet.internet is not None):
                                output += packet.internet.print()
                            if (packet.transport is not None):
                                output += packet.transport.print()
                            output += printHex(packet.data, 16) + "\n\n"
                        else:
                            output += BLANK_PACKET
                    break

        if (clearTextBox()):
            if (createTextBox()):
                if (isChecked):
                    stringToFile("4b_output.txt", output)
                    textBox.insert(INSERT, "Output written to file " + "4b_output.txt")
                else:
                    textBox.insert(INSERT, output)

        textBox.config(state=DISABLED)

def fourCTask(isChecked):
    if (isLoaded):
        output = ""
        if (not len(TELNET_LIST_PURE)):
            output = "No TELNET packets found!"
        else:
            output += "Kompletné komunikácie:\n\n"
            counter = 0
            for i in range(0, len(TELNET_LIST)):
                if (TELNET_LIST[i][1]):
                    counter += 1
                    output += "Komunikácia č." + str(counter) + "\n"
                    for index in range(0, len(TELNET_LIST[i][0])):
                        packet = TELNET_LIST[i][0][index]
                        if (index < int(MAX / 2) or index >= int(len(TELNET_LIST[i][0]) - (MAX / 2))):
                            output += packet.print() + packet.networkAccess.print()
                            if (packet.internet is not None):
                                output += packet.internet.print()
                            if (packet.transport is not None):
                                output += packet.transport.print()
                            output += printHex(packet.data, 16) + "\n\n"
                        else:
                            output += BLANK_PACKET
                    break

            counter = 0
            output += "Nekompletné komunikácie:\n\n"
            for i in range(0, len(TELNET_LIST)):
                if (not TELNET_LIST[i][1]):
                    counter += 1
                    output += "Komunikácia č." + str(counter) + "\n"
                    for index in range(0, len(TELNET_LIST[i][0])):
                        packet = TELNET_LIST[i][0][index]
                        if (index < int(MAX / 2) or index >= int(len(TELNET_LIST[i][0]) - (MAX / 2))):
                            output += packet.print() + packet.networkAccess.print()
                            if (packet.internet is not None):
                                output += packet.internet.print()
                            if (packet.transport is not None):
                                output += packet.transport.print()
                            output += printHex(packet.data, 16) + "\n\n"
                        else:
                            output += BLANK_PACKET
                    break

        if (clearTextBox()):
            if (createTextBox()):
                if (isChecked):
                    stringToFile("4c_output.txt", output)
                    textBox.insert(INSERT, "Output written to file " + "4c_output.txt")
                else:
                    textBox.insert(INSERT, output)

        textBox.config(state=DISABLED)

def fourDTask(isChecked):
    if (isLoaded):
        output = ""
        if (not len(SSH_LIST_PURE)):
            output = "No SSH packets found!"
        else:
            output += "Kompletné komunikácie:\n\n"
            counter = 0
            for i in range(0, len(SSH_LIST)):
                if (SSH_LIST[i][1]):
                    counter += 1
                    output += "Komunikácia č." + str(counter) + "\n"
                    for index in range(0, len(SSH_LIST[i][0])):
                        packet = SSH_LIST[i][0][index]
                        if (index < int(MAX / 2) or index >= int(len(SSH_LIST[i][0]) - (MAX / 2))):
                            output += packet.print() + packet.networkAccess.print()
                            if (packet.internet is not None):
                                output += packet.internet.print()
                            if (packet.transport is not None):
                                output += packet.transport.print()
                            output += printHex(packet.data, 16) + "\n\n"
                        else:
                            output += BLANK_PACKET
                    break

            counter = 0
            output += "Nekompletné komunikácie:\n\n"
            for i in range(0, len(SSH_LIST)):
                if (not SSH_LIST[i][1]):
                    counter += 1
                    output += "Komunikácia č." + str(counter) + "\n"
                    for index in range(0, len(SSH_LIST[i][0])):
                        packet = SSH_LIST[i][0][index]
                        if (index < int(MAX / 2) or index >= int(len(SSH_LIST[i][0]) - (MAX / 2))):
                            output += packet.print() + packet.networkAccess.print()
                            if (packet.internet is not None):
                                output += packet.internet.print()
                            if (packet.transport is not None):
                                output += packet.transport.print()
                            output += printHex(packet.data, 16) + "\n\n"
                        else:
                            output += BLANK_PACKET
                    break

        if (clearTextBox()):
            if (createTextBox()):
                if (isChecked):
                    stringToFile("4d_output.txt", output)
                    textBox.insert(INSERT, "Output written to file " + "4d_output.txt")
                else:
                    textBox.insert(INSERT, output)

        textBox.config(state=DISABLED)

def fourETask(isChecked):
    if (isLoaded):
        output = ""
        if (not len(FTP_CONTROL_LIST_PURE)):
            output = "No FTP-control packets found!"
        else:
            output += "Kompletné komunikácie:\n\n"
            counter = 0
            for i in range(0, len(FTP_CONTROL_LIST)):
                if (FTP_CONTROL_LIST[i][1]):
                    counter += 1
                    output += "Komunikácia č." + str(counter) + "\n"
                    for index in range(0, len(FTP_CONTROL_LIST[i][0])):
                        packet = FTP_CONTROL_LIST[i][0][index]
                        if (index < int(MAX / 2) or index >= int(len(FTP_CONTROL_LIST[i][0]) - (MAX / 2))):
                            output += packet.print() + packet.networkAccess.print()
                            if (packet.internet is not None):
                                output += packet.internet.print()
                            if (packet.transport is not None):
                                output += packet.transport.print()
                            output += printHex(packet.data, 16) + "\n\n"
                        else:
                            output += BLANK_PACKET
                    break

            counter = 0
            output += "Nekompletné komunikácie:\n\n"
            for i in range(0, len(FTP_CONTROL_LIST)):
                if (not FTP_CONTROL_LIST[i][1]):
                    counter += 1
                    output += "Komunikácia č." + str(counter) + "\n"
                    for index in range(0, len(FTP_CONTROL_LIST[i][0])):
                        packet = FTP_CONTROL_LIST[i][0][index]
                        if (index < int(MAX / 2) or index >= int(len(FTP_CONTROL_LIST[i][0]) - (MAX / 2))):
                            output += packet.print() + packet.networkAccess.print()
                            if (packet.internet is not None):
                                output += packet.internet.print()
                            if (packet.transport is not None):
                                output += packet.transport.print()
                            output += printHex(packet.data, 16) + "\n\n"
                        else:
                            output += BLANK_PACKET
                    break

        if (clearTextBox()):
            if (createTextBox()):
                if (isChecked):
                    stringToFile("4e_output.txt", output)
                    textBox.insert(INSERT, "Output written to file " + "4e_output.txt")
                else:
                    textBox.insert(INSERT, output)

        textBox.config(state=DISABLED)

def fourFTask(isChecked):
    if (isLoaded):
        output = ""
        if (not len(FTP_DATA_LIST_PURE)):
            output = "No FTP-data packets found!"
        else:
            output += "Kompletné komunikácie:\n\n"
            counter = 0
            for i in range(0, len(FTP_DATA_LIST)):
                if (FTP_DATA_LIST[i][1]):
                    counter += 1
                    output += "Komunikácia č." + str(counter) + "\n"
                    for index in range(0, len(FTP_DATA_LIST[i][0])):
                        packet = FTP_DATA_LIST[i][0][index]
                        if (index < int(MAX / 2) or index >= int(len(FTP_DATA_LIST[i][0]) - (MAX / 2))):
                            output += packet.print() + packet.networkAccess.print()
                            if (packet.internet is not None):
                                output += packet.internet.print()
                            if (packet.transport is not None):
                                output += packet.transport.print()
                            output += printHex(packet.data, 16) + "\n\n"
                        else:
                            output += BLANK_PACKET
                    break

            counter = 0
            output += "Nekompletné komunikácie:\n\n"
            for i in range(0, len(FTP_DATA_LIST)):
                if (not FTP_DATA_LIST[i][1]):
                    counter += 1
                    output += "Komunikácia č." + str(counter) + "\n"
                    for index in range(0, len(FTP_DATA_LIST[i][0])):
                        packet = FTP_DATA_LIST[i][0][index]
                        if (index < int(MAX / 2) or index >= int(len(FTP_DATA_LIST[i][0]) - (MAX / 2))):
                            output += packet.print() + packet.networkAccess.print()
                            if (packet.internet is not None):
                                output += packet.internet.print()
                            if (packet.transport is not None):
                                output += packet.transport.print()
                            output += printHex(packet.data, 16) + "\n\n"
                        else:
                            output += BLANK_PACKET
                    break

        if (clearTextBox()):
            if (createTextBox()):
                if (isChecked):
                    stringToFile("4f_output.txt", output)
                    textBox.insert(INSERT, "Output written to file " + "4f_output.txt")
                else:
                    textBox.insert(INSERT, output)

        textBox.config(state=DISABLED)

def fourGTask(isChecked):
    if (isLoaded):
        output = ""
        if (not len(TFTP_LIST_PURE)):
            output = "No TFTP packets found!"
        else:
            for i in range(0, len(TFTP_LIST)):
                output += "Komunikácia č." + (str(i + 1)) + "\n"
                for index in range(0, len(TFTP_LIST[i])):
                    packet = TFTP_LIST[i][index]
                    if (index < int(MAX / 2) or index >= int(len(TFTP_LIST[i]) - (MAX / 2))):
                        output += packet.print() + packet.networkAccess.print()
                        output += packet.internet.print()
                        output += packet.transport.print()
                        output += packet.application.print()
                        output += printHex(packet.data, 16) + "\n\n"

                output += "\n\n"

        if (clearTextBox()):
            if (createTextBox()):
                if (isChecked):
                    stringToFile("4g_output.txt", output)
                    textBox.insert(INSERT, "Output written to file " + "4g_output.txt")
                else:
                    textBox.insert(INSERT, output)

        textBox.config(state=DISABLED)

def fourHTask(isChecked):
    if (isLoaded):
        if (not len(ICMP_LIST_PURE)):
            output = "No ICMP packets found!"
        else:
            output = ""
            for i in range(0, len(ICMP_LIST)):
                output += "Komunikácia č." + (str(i + 1)) + "\n"
                for index in range(0, len(ICMP_LIST[i])):
                    packet = ICMP_LIST[i][index]
                    if (index < int(MAX / 2) or index >= int(len(ICMP_LIST[i]) - (MAX / 2))):
                        output += packet.print() + packet.networkAccess.print()
                        output += packet.internet.print()
                        output += packet.transport.print()
                        output += printHex(packet.data, 16) + "\n\n"
                    else:
                        output += BLANK_PACKET
                output += "\n\n"
        if (clearTextBox()):
            if (createTextBox()):
                if (isChecked):
                    stringToFile("4h_output.txt", output)
                    textBox.insert(INSERT, "Output written to file " + "4h_output.txt")
                else:
                    textBox.insert(INSERT, output)

        textBox.config(state=DISABLED)

def fourITask(isChecked):
    if (isLoaded):
        if (not len(ARP_LIST_PURE)):
            output = "No ARP packets found!"
        else:
            output = ""
            output += "Kompletná komunikácia (ARP REQUEST-REPLY):" + "\n\n"
            counter = 0
            for i in range(0, len(ARP_LIST)):
                if(ARP_LIST[i][1]):
                    counter += 1
                    output += "Komunikácia č. " + str(counter) + "\n"
                    for index in range(0, len(ARP_LIST[i][0])):
                        packet = ARP_LIST[i][0][index]
                        if (index < int(MAX / 2) or index >= int(len(ARP_LIST[i]) - (MAX / 2))):
                            output += packet.print() + packet.networkAccess.print()
                            if (packet.internet is not None):
                                output += packet.internet.print()
                            if (packet.transport is not None):
                                output += packet.transport.print()
                            output += printHex(packet.data, 16) + "\n\n"
                        else:
                            output += BLANK_PACKET
                    output += "\n\n"

            output += "Nekompletná komunikácia (ARP REQUEST-REPLY):" + "\n\n"
            counter = 0
            for i in range(0, len(ARP_LIST)):
                if (not ARP_LIST[i][1]):
                    counter += 1
                    output += "Komunikácia č. " + str(counter) + "\n"
                    for index in range(0, len(ARP_LIST[i][0])):
                        packet = ARP_LIST[i][0][index]
                        if (index < int(MAX / 2) or index >= int(len(ARP_LIST[i]) - (MAX / 2))):
                            output += packet.print() + packet.networkAccess.print()
                            if (packet.internet is not None):
                                output += packet.internet.print()
                            if (packet.transport is not None):
                                output += packet.transport.print()
                            output += printHex(packet.data, 16) + "\n\n"
                        else:
                            output += BLANK_PACKET
                    output += "\n\n"

        if (clearTextBox()):
            if (createTextBox()):
                if (isChecked):
                    stringToFile("4i_output.txt", output)
                    textBox.insert(INSERT, "Output written to file " + "4i_output.txt")
                else:
                    textBox.insert(INSERT, output)

        textBox.config(state=DISABLED)

def createCopiesAndTCPComm(original, pureVersion):
    pureVersion.clear()
    pureVersion.extend(original)
    original.clear()
    original.extend(TCPCommunications(pureVersion.copy()))

def communicationsLoader():

    createCopiesAndTCPComm(HTTP_LIST, HTTP_LIST_PURE)
    createCopiesAndTCPComm(HTTPS_LIST, HTTPS_LIST_PURE)
    createCopiesAndTCPComm(TELNET_LIST, TELNET_LIST_PURE)
    createCopiesAndTCPComm(SSH_LIST, SSH_LIST_PURE)
    createCopiesAndTCPComm(FTP_CONTROL_LIST, FTP_CONTROL_LIST_PURE)
    createCopiesAndTCPComm(FTP_DATA_LIST, FTP_DATA_LIST_PURE)

    ICMP_LIST_PURE.clear()
    ICMP_LIST_PURE.extend(ICMP_LIST)
    ICMP_LIST.clear()
    ICMP_LIST.extend(ICMPCommunicationPairs(ICMP_LIST_PURE.copy()))

    TFTP_LIST_PURE.clear()
    TFTP_LIST_PURE.extend(TFTP_LIST)
    TFTP_LIST.clear()
    TFTP_LIST.extend(TFTPResolver(TFTP_LIST_PURE.copy(), packets))

    ARP_LIST_PURE.clear()
    ARP_LIST_PURE.extend(ARP_LIST)
    ARP_LIST.clear()
    ARP_LIST.extend(ARPPairResolver(ARP_LIST_PURE.copy()))


def loader(packetArray):
    global isLoaded
    if(len(packetArray) > 0):
        packets.clear()
        HTTP_LIST.clear()
        HTTPS_LIST.clear()
        TELNET_LIST.clear()
        SSH_LIST.clear()
        FTP_CONTROL_LIST.clear()
        FTP_DATA_LIST.clear()
        TFTP_LIST.clear()
        ICMP_LIST.clear()
        ARP_LIST.clear()

        HTTP_LIST_PURE.clear()
        HTTPS_LIST_PURE.clear()
        TELNET_LIST_PURE.clear()
        SSH_LIST_PURE.clear()
        FTP_CONTROL_LIST_PURE.clear()
        FTP_DATA_LIST_PURE.clear()
        TFTP_LIST_PURE.clear()
        ICMP_LIST_PURE.clear()
        ARP_LIST_PURE.clear()
        isLoaded = False

    if(packetArray and len(packets) == 0):
        for pos in range(0, len(packetArray)):
            packets.append(Packet(packetArray[pos], pos+1))

    if(len(packets) > 0):
        isLoaded = True
        communicationsLoader()
        popUP("Data loaded successfully!")
        print("Data loaded successfully!\n")



def loadFile(root):
    global packets
    file = tkinter.filedialog.askopenfilename(filetype=[("Wireshark packet capture", ".pcap")])
    if (file):
        popUP("File loaded successfully!")
        print("File loaded successfully!")
        packetArray = hexpackets(rdpcap(file))
        if(packetArray):
            loader(packetArray)
            global FILE_NAME
            FILE_NAME = fileName(file)
            show(root, FILE_NAME)
            statistics()
            doimplementacia()

def doimplementacia():
    print("POCET PIM RAMCOV:", len(PIM_LIST))
    output = ""
    for packet in PIM_LIST:
        output += packet.print() + packet.networkAccess.print()
        if (packet.internet is not None):
            output += packet.internet.print()
        if (packet.transport is not None):
            output += packet.transport.print()
        output += printHex(packet.data, 16) + "\n\n"

    print(output)

def statistics(): #statistiky
    if(isLoaded):
        ethIIAmount = 0
        llcAmount = 0
        llcSNAPAmount = 0
        novellRAWAmount = 0

        ipv4Amount = 0
        arpAmount = 0

        tcpAmount = 0
        udpAmount = 0
        icmpAmount = 0

        httpAmount = 0
        httpsAmount = 0
        sshAmount = 0
        telnetAmount = 0
        ftpControlAmount = 0
        ftpDataAmount = 0
        tftpAmount = 0

        for packet in packets:
            if(packet.networkAccess is not None):
                if(packet.networkAccess.frameType == "Ethernet II"):
                    ethIIAmount += 1
                elif (packet.networkAccess.frameType == "Novell 802.3 RAW"):
                    novellRAWAmount += 1
                elif(packet.networkAccess.frameType == "802.3 LLC"):
                    llcAmount += 1
                elif(packet.networkAccess.frameType == "802.3 LLC + SNAP"):
                    llcSNAPAmount += 1
            if(packet.internet is not None):
                match vartype(type(packet.internet)):
                    case 'IPv4':
                        ipv4Amount += 1
                    case 'ARP':
                        arpAmount += 1
            if(packet.transport is not None):
                match vartype(type(packet.transport)):
                    case 'TCP':
                        tcpAmount += 1
                    case 'UDP':
                        udpAmount += 1
                    case 'ICMP':
                        icmpAmount += 1
            if(packet.application is not None):
                match vartype(type(packet.application)):
                    case 'HTTP':
                        httpAmount += 1
                    case 'HTTPS':
                        httpsAmount += 1
                    case 'SSH':
                        sshAmount += 1
                    case 'TELNET':
                        telnetAmount += 1
                    case 'FTP_CONTROL':
                        ftpControlAmount += 1
                    case 'FTP_DATA':
                        ftpDataAmount += 1
                    case 'TFTP':
                        tftpAmount += 1

        output = ""
        output += "Statistics for " + FILE_NAME + ":\n"
        output += "Total packets: " + str(len(packets)) + "\n"
        output += "Network Access Layer:\n"
        output += "Ethernet II: " + str(ethIIAmount) + "\n"
        output += "Novell 802.3 RAW: " + str(novellRAWAmount) + "\n"
        output += "802.3 LLC: " + str(llcAmount) + "\n"
        output += "802.3 LLC + SNAP: " + str(llcSNAPAmount) + "\n\n"
        output += "Internet Layer:\n"
        output += "IPv4: " + str(ipv4Amount) + "\n"
        output += "ARP: " + str(arpAmount) + "\n\n"
        output += "Transport Layer:\n"
        output += "TCP: " + str(tcpAmount) + "\n"
        output += "UDP: " + str(udpAmount) + "\n"
        output += "ICMP: " + str(icmpAmount) + "\n\n"
        output += "Application Layer:\n"
        output += "HTTP: " + str(httpAmount) + "\n"
        output += "HTTPS: " + str(httpsAmount) + "\n"
        output += "TELNET: " + str(telnetAmount) + "\n"
        output += "SSH: " + str(sshAmount) + "\n"
        output += "FTP CONTROL: " + str(ftpControlAmount) + "\n"
        output += "FTP DATA: " + str(ftpDataAmount) + "\n"
        output += "TFTP: " + str(tftpAmount) + "\n"

        print(output + "\n\n")


def main():
    global root
    root = Tk()
    menu = Menu(root)
    root.config(menu=menu)
    root.title(TITLE_NAME)
    openFileButton = Button(root, text="Open pcap file", command=lambda: loadFile(root))
    openFileButton.pack(side=tkinter.TOP)
    openFileButton.pack(side=tkinter.TOP)
    mainloop()

if __name__ == '__main__':
    main()

