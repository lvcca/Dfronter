# Author :     Mason Palma
# File :       PacketGrabber.py
# Date :       30OCT2020
# Purpose :    To provide skeleton class of domain fronting detection software

import socket
from dataclasses import dataclass
from ctypes import *
import struct
import threading
import datetime

our_domain = socket.gethostbyname(socket.gethostname())
targetList = []
target_not_malicious = []
domain_frontable = []
no_fqdn = []
fqdns = []
query_list = []

@dataclass
class TargetStructure:
   # Example of how to assign fields of object
   # test = TargetStructure(full_URI="this is a test", domain="asd", time_stamp="asdasd", packet_size="asdasdasd")
   _fields_ = [
      ('full_URI', str),
      ('domain', str),
      ('time_stamp', str),
      ('packet_size', str)
   ]

   def __init__(self, full_URI, domain, time_stamp, packet_size):

      if full_URI:
         self.full_URI = full_URI
      if domain:
         self.domain = domain
      if time_stamp:
         self.time_stamp = time_stamp
      if packet_size:
         self.packet_size = packet_size

      else:
         try:
            self.full_URI = self.full_URI
            self.domain = self.domain
            self.time_stamp = self.time_stamp
            self.packet_size = self.packet_size

         except:
            self.full_URI = str(self.full_URI)
            self.domain = str(self.domain)
            self.time_stamp = str(self.time_stamp)
            self.packet_size = str(self.packet_size)

test = TargetStructure("asdasdasdasd","asdasdasd","asdasd","asd")

def add_to_list_target_list(target):
   # Example of how to add to list
   # addToList(test)
   global targetList
   targetList.append(target)


def add_to_list_not_malicious(target):
   global target_not_malicious
   target_not_malicious.append(target)


class UDP_H(Structure):

   _fields_ = [

      ("src_port", c_ushort, 16),
      ("dst_port", c_ushort, 16),
      ("len", c_ushort, 16),
      ("sum", c_ushort, 16),
      ("data", c_ubyte)

   ]

   def __new__(self, socket_buffer=None):
      return self.from_buffer_copy(socket_buffer)


class TCP_H(Structure):

   _fields_ = [

      ("src_port", c_ushort),
      ("dst_port", c_ushort),
      ("seq", c_ulong),
      ("ack", c_ulong),
      ("offset", c_ubyte),
      ("reserved", c_ubyte),
      ("flags", c_ubyte),
      ("window_size", c_uint),
      ("sum", c_ushort),
      ("urg", c_ubyte),
      ("optional", c_ubyte)

   ]
   
   def __new__(self, socket_buffer=None):
      return self.from_buffer_copy(socket_buffer)


class IP(Structure):

   _fields_ = [
      ("ih1", c_ubyte, 4),
      ("version", c_ubyte, 4),
      ("tos", c_ubyte, 8),
      ("len", c_ushort, 16),
      ("id", c_ushort, 16),
      ("offset", c_ushort, 16),
      ("ttl", c_ubyte, 8),
      ("protocol_num", c_ubyte, 8),
      ("sum", c_ushort, 16),
      ("src", c_uint, 32),
      ("dst", c_uint, 32),
      #BEGIN TCP/UDP Header
      ("src_port", c_ushort, 16),
      ("dst_port", c_ushort, 16)
      #("TCP_seq", c_uint32)
      #("TCP_ack", c_uint32),
      #("TCP_Hlen", c_uint, 4),
      #("TCP_Reserved", c_byte, 4),
      #("TCP_Flags", c_uint8),
      #("TCP_Window", c_uint16),
      #("TCP_SUM", c_ushort, 16),
      #("TCP_URG_POINTER", c_ushort, 16),
      #("TCP_Options", c_ubyte, 32),
      #("TCP_Data", c_ubyte)
   ]

   def __new__(self, socket_buffer=None):
      return self.from_buffer_copy(socket_buffer)

   def __init__(self, socket_buffer=None):

      self.protocol_map = {1: "ICMP", 2: "IGMP", 4: "IP in IP", 6: "TCP", 17: "UDP", 27: "RDP"}

      self.src_address = socket.inet_ntoa(struct.pack("<I", self.src))
      self.dst_address = socket.inet_ntoa(struct.pack("<I", self.dst))
      self.src_port = socket.ntohs(int(self.src_port))
      self.dst_port = socket.ntohs(int(self.dst_port))
      self.len = socket.ntohs(int(self.len))
      self.id = socket.ntohs(int(self.id))

      try:
         self.protocol = self.protocol_map[self.protocol_num]
         self.ip_version = self.version
         self.ih1 = self.ih1

         #self.TCP_seq = socket.ntohs(int(self.TCP_seq))

      except:
         self.protocol = str(self.protocol_num)
         self.ip_version = str(self.version)
         self.ih1 = str(self.ih1)



def capture_live(host=socket.gethostname(), port=0):

   global targetList
   global target_not_malicious
   global no_fqdn
   global domain_frontable

   try:
      host = "192.168.1.153"
      s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
      s.bind((host, port))
      s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
      s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

      raw_buffer = s.recvfrom(65565)[0]
      ip_header = IP(raw_buffer[:])

      print("[%s] %s:%s -> %s:%s, Total Length: %s, IPV%s, ID: %s" % (ip_header.protocol,
         ip_header.src_address, ip_header.src_port, ip_header.dst_address, ip_header.dst_port, ip_header.len,
            ip_header.ip_version, ip_header.id))

      if ip_header.src_address not in targetList:
         if ip_header.src_address not in target_not_malicious:
            if ip_header.src_address not in no_fqdn:
               if ip_header.src_address not in fqdns:
                  if ip_header.src_address not in domain_frontable:
                     add_to_list_target_list(ip_header.src_address)

      if ip_header.dst_address not in targetList:
         if ip_header.dst_address not in target_not_malicious:
            if ip_header.dst_address not in no_fqdn:
               if ip_header.dst_address not in fqdns:
                  if ip_header.dst_address not in domain_frontable:
                     add_to_list_target_list(ip_header.dst_address)

      s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
      s.close()

   except KeyboardInterrupt:
      s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
      s.close()

   except:
      s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
      s.close()


def find_fqdn():
   global targetList
   global target_not_malicious
   global no_fqdn
   global fqdns

   for target in targetList:
      try:
         fqdn = socket.gethostbyaddr(target)[0]
         fqdns.append(target)
         targetList.remove(target)

      except:
         no_fqdn.append(target)
         targetList.remove(target)


def get_query(domain, port=80, recv_size=1024):
   global our_domain
   addr = (domain, port)

   get = (b"GET / HTTP/1.1\r\n" +
          b"User-Agent: Mozilla/4.0\r\n" +
          b"Host: %s\r\n" % bytes(our_domain, "utf-8") +
          b"Accepts: */* \r\n\r\n")
   try:

      with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
         s.settimeout(2)
         s.connect(addr)
         s.sendall(get)
         r = s.recv(recv_size)
         s.close()
      return repr(r)

   except:
      print("Something went wrong in get_query for " + domain)


def make_query_FQDN():
   global targetList
   global target_not_malicious
   global no_fqdn
   global fqdns
   global domain_frontable
   global query_list

   try:
      for target in fqdns:
         r = get_query(target)
         if "200 OK" in r:
            domain_frontable.append(target)
            fqdns.remove(target)

            # obtain larger recv from host if 200 OK, full http response
            r_2 = get_query(target, recv_size=65536)
            query_list.append(r_2)
         else:
            target_not_malicious.append(target)
            fqdns.remove(target)
         print(r)
   except:
      print("Could not make connection for: " + target)
      target_not_malicious.append(target)
      fqdns.remove(target)


def make_query_no_FQDN():
   global targetList
   global target_not_malicious
   global no_fqdn
   global fqdns
   global domain_frontable
   global query_list

   try:
      for target in no_fqdn:
         r = get_query(target)
         if "200 OK" in r:
            domain_frontable.append(target)
            no_fqdn.remove(target)

            # obtain larger recv from host if 200 OK, full http response
            r_2 = get_query(target, recv_size=65536)
            query_list.append(r_2)
         else:
            target_not_malicious.append(target)
            no_fqdn.remove(target)
         print(r)
   except:
      print("Could not make connection for: " + target)
      target_not_malicious.append(target)
      no_fqdn.remove(target)

while True:
   capture_live()
   print("Target list: " + str(len(targetList)))
   find_fqdn()
   print("No FQDN: " + str(len(no_fqdn)))
   print("From FQDNs: " + str(len(fqdns)))
   make_query_FQDN()
   make_query_no_FQDN()
   print(fqdns[:])
   print("Domain frontable: " + str(len(domain_frontable)) + " " + str(domain_frontable[:]))
   print("Not Malicious targets: " + str(len(target_not_malicious)))
   print("Query List Size: " + str(len(query_list)))
