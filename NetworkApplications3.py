#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback # useful for exception handling
import threading

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='neverssl.com')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_pt = subparsers.add_parser('paris-traceroute', aliases=['pt'],
                                         help='run paris-traceroute')
        parser_pt.set_defaults(timeout=4, protocol='icmp')
        parser_pt.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_pt.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_pt.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_pt.set_defaults(func=ParisTraceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printMultipleResults(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))

class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout, sendtime):
        IDcheck = ID
        try:
            reply = icmpSocket.recv(4096)
        except icmpSocket.timeout:
            print("Packet not recieved")
        reply = reply[20:28]
        i = 0
        while not reply:
            i+=1
            time.sleep(1)
            if i == 10:
                print("Recieve timed out")
                break
        recievetime = (time.time()*1000)
        Type, code, checksum, IDVerify, seqNum = struct.unpack("BBHHH",reply)
        #print(Type, code, checksum, IDVerify, seqNum)
        return recievetime
      
    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        icmpHeader = struct.pack("BBHHH", 8,0, 0, ID, 0)
        checksum = self.checksum(icmpHeader)
        icmpHeader = struct.pack("BBHHH",8,0, checksum,  ID, 0)
        icmpSocket.sendto(icmpHeader, (destinationAddress, 80))
        sendtime = (time.time()*1000)
        return sendtime
        
    def doOnePing(self, destinationAddress,timeout):
        Icmpsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        timeout = Icmpsocket.settimeout(10)
        sendTime = self.sendOnePing(Icmpsocket, destinationAddress,1)
        recieveTime = self.receiveOnePing(Icmpsocket, destinationAddress,1,timeout,1)
        Icmpsocket.close()
        totalDelay = recieveTime-sendTime
        return totalDelay

    #def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        IP = socket.gethostbyname(args.hostname)
        while True:
            self.printOneResult(IP, 8, self.doOnePing(IP,1) , 1)
            time.sleep(1) 

class Traceroute(NetworkApplication):# Paris traceroute for ICMP works with bbc.co.uk

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout, sendtime):
        IDcheck = ID
        try:
            reply = icmpSocket.recv(4096)
        except socket.timeout:
            print("Packet not recieved")
            return -1

        reply = reply[20:28]  
        recievetime = (time.time()*1000)
        Type, code, checksum, IDVerify, seqNum = struct.unpack("BBHHH",reply)
        if reply[0] == self.IP:
            print("Found")
        return recievetime,Type

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        icmpHeader = struct.pack("BBHHH", 8,0, 0, ID, 0)
        checksum = self.checksum(icmpHeader)
        icmpHeader = struct.pack("BBHHH",8,0, checksum,  ID, 0)
        icmpSocket.sendto(icmpHeader, (destinationAddress, 80))
        sendtime = (time.time()*1000)
        return sendtime

    def doOnePing(self, destinationAddress, timeout):
        Icmpsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        Icmpsocket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.TTL)
        timeout = Icmpsocket.settimeout(5)
        sendTime = self.sendOnePing(Icmpsocket, destinationAddress,1)
        recieveTime = self.receiveOnePing(Icmpsocket, destinationAddress,1,timeout,1)
        if recieveTime == -1:
            print("Invalid Time")
            return 0,5 
        else:
            Icmpsocket.close()
            totalDelay = recieveTime[0]-sendTime
            return totalDelay, recieveTime[1]
    
    def __init__(self, args):
        print('Traceroute to: %s...' % (args.hostname))
        self.IP = socket.gethostbyname(args.hostname)
        self.TTL = 1
        while True:
            results = self.doOnePing(self.IP,1)
            print(results)
            if results[1] == 0:
                self.printOneResult(self.IP, 8, results[0], self.TTL, args.hostname)
                print("Packet has reached destination")
                break
            else:
                self.printOneResult(self.IP, 8, results[0], self.TTL, args.hostname)
                self.TTL += 1
            

class ParisTraceroute(NetworkApplication):#Working implementation for udp paris traceroute, managed to send udp packets but always times out before reaching the server and then stops.

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout, sendtime):
        IDcheck = ID
        try:
            reply = icmpSocket.recv(4096)
        except socket.timeout:
            print("Packet not recieved")
            return -1

        reply = reply[20:28]  
        recievetime = (time.time()*1000)
        Type, code, checksum, IDVerify, seqNum = struct.unpack("BBHHH",reply)
        print(reply[0])
        print(self.IP)
        if reply[0] == self.IP:
            print("Found")
        return recievetime,Type

    def sendOnePing(self, udpSocket, destPort, sourcePort, icmpSocket, destinationAddress, ID, Checksum):
            data = (b"Hello World")
            icmpHeader = struct.pack("BBHHH", 8,0, 0, ID, 0)
            IcmpChecksum = self.checksum(icmpHeader)
            icmpHeader = struct.pack("BBHHH",8,0, IcmpChecksum,  ID, 0)
            headLength = 8+len(icmpHeader)
            udpHeader = struct.pack("IIII", sourcePort, destPort, headLength, Checksum)
            udpChecksum = self.checksum(udpHeader)
            udpHeader = struct.pack("IIII", sourcePort, destPort, headLength, udpChecksum)
            packetWhole = udpHeader + icmpHeader + data
            udpSocket.sendto(packetWhole, (destinationAddress, destPort))
            sendtime = (time.time()*1000)
            return sendtime

    def doOnePing(self, destinationAddress, timeout, Checksum):
        destPort = 35000
        sourcePort = destPort
        Icmpsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        timeout = Icmpsocket.settimeout(10)
        udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        udpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.TTL)
        udpSocket.bind(("",destPort))
        sendTime = self.sendOnePing(udpSocket, destPort, sourcePort, Icmpsocket, destinationAddress,1,Checksum)
        recieveTime = self.receiveOnePing(Icmpsocket, destinationAddress,1,timeout,1)
        udpSocket.close()
        Icmpsocket.close()
        
        if recieveTime == -1:
            print("Invalid Time")
            return 0,5 
        else:
            totalDelay = recieveTime[0]-sendTime
            return totalDelay, recieveTime[1]
    
    def __init__(self, args):
        print('Traceroute to: %s...' % (args.hostname))
        self.IP = socket.gethostbyname(args.hostname)
        self.TTL = 1
        Checksum = 0
        while True:
            results = self.doOnePing(self.IP,1,Checksum)
            print(results)
            if results[1] == 0:
                self.printOneResult(self.IP, 8, results[0], self.TTL, args.hostname)
                print("Packet has reached destination")
                break
            else:
                self.printOneResult(self.IP, 8, results[0], self.TTL, args.hostname)
                self.TTL += 1
                Checksum += 256

class WebServer(NetworkApplication):

    def handleRequest(self,conn, Addr):
        print(f"New connection {Addr} received.")
        try:
            requestMsg = conn.recv(4096)
            print(requestMsg)   
        except socket.timeout:
            print("Request timed out")
            conn.close()

        objPath = requestMsg.split()[1]
        htmlFile = open(objPath[1:])
        tempBuf = htmlFile.read()
        htmlFile.close 
        errMsg = 'HTTP/1.0 200 OK\r\n\r\n'
        conn.send(errMsg.encode())
        for i in range(0, len(tempBuf)):
            conn.send(tempBuf[i].encode())
        conn.close()

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        ServerIP = socket.gethostbyname(socket.gethostname())
        print(ServerIP)
        ADDR = (ServerIP, args.port)
        ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        ServerSocket.bind(ADDR)
        ServerSocket.listen(1)
        while True:
            conn, Addr = ServerSocket.accept()
            clientThread = threading.Thread(target = self.handleRequest, args = (conn, Addr))
            clientThread.start()
            print("Active Thread Count" , threading.active_count()-1)

class Proxy(NetworkApplication):

    def handleRequest(self,conn, Addr):
        print("Active Thread Count" , threading.active_count()-1)
        WebSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        print(f"New connection {Addr} received.")
        try:
            requestMsg = conn.recv(4096)
        except socket.error:
            print("Request timed out")
            conn.close()

        requestMsg = requestMsg.split()
        objPath = requestMsg[1].decode("utf-8")
        print(objPath)
        WebSocket.connect((requestMsg[4],80))
        y = (len(requestMsg[4])+7)
        objPath = objPath[y:]
        sendMsg = ("GET "+objPath+"/ "+requestMsg[2].decode("utf-8")+"\r\nHost:"+requestMsg[4].decode("utf-8")+"\r\n\r\n")
        print(sendMsg)
        print(str.encode(sendMsg))
        WebSocket.send(str.encode(sendMsg))
        try:
            replyMsg = WebSocket.recv(4096)
            WebSocket.close()
        except socket.error:
            print("Request timed out")
            conn.close()
            
        conn.send(replyMsg)
        WebSocket.close()
        conn.close()
        
    def __init__(self, args):
        print('Proxy Server starting on port: %i...' % (args.port))
        ServerIP = socket.gethostbyname(socket.gethostname())
        ADDR = (ServerIP, args.port)
        ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        ServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ServerSocket.bind(ADDR)
        ServerSocket.listen()
        while True:
            conn, Addr = ServerSocket.accept()
            clientThread = threading.Thread(target = self.handleRequest, args = (conn, Addr))
            clientThread.start()

if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
