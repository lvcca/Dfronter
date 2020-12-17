# Author: Mason Palma & Sean Fern
# File: DFronter_v1.py
# Date: 13DEC2020
# Purpose: Parses network packet header data in order to identify possible domain 
# fronting C2 actvity for further analysis.

import argparse
import os
import sys
import re
import socket
import struct
import ctypes
import json
import dpkt
import signal
from dpkt.ip import IP_PROTO_TCP, IP_PROTO_UDP
from dpkt.http import Request, Response
from dpkt.compat import compat_ord

# Global lists
target_dict = {}
targetList_dst = []
targetList_src = []
target_not_malicious = []
no_fqdn = []
fqdns = []
cdn_domains = []
domain_frontable = []
query_list = []

hostOS = os.name
host = socket.gethostname()
our_domain = socket.gethostbyname(host)

silentMode = False

IFF_PROMISC = 0x100
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914

# for cdn enum
enum_list = []
for number in range(26):
    enum_list.append(number)

def interrupt_handler(signum, frame):
    print("[*] Quitting...")
    #sys.exit(-2)
    write_outfile(output)
    sys.exit()


signal.signal(signal.SIGINT, interrupt_handler)

# Regex for server/tld
# ([.][a-zA-Z]+[.][a-zA-Z]+)
# Regex for IP address
#   (([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])[.]){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])
# Regex for URL
#   \/([a-zA-Z0-9]+)[.]?([a-zA-Z])+|([a-zA-Z/])+
# s_addr, source_port, d_addr, dest_port, domain, data_size, data

if "posix" in hostOS:
    import libpcap
    import fcntl

    def get_ip_address(ifname):
        """Obtain IP address of active interface.
        Args:
            param ifname (int): collection interface.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])


class TargetStructure:
    dst = ""
    src = ""
    src_port = ""
    dst_port = ""
    domain = ""
    packet_size = ""
    data = ""
    resource = ""
    host_hdr = ""
    protocol = ""
    http_headers = []


class ifreq(ctypes.Structure):
    """Define fields needed for posix sockets."""
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]


def capture_live(host=socket.gethostname(), port=0):
    """Begin packet capture of specified host and port.
    Args:
        param host (string): host performing packet collection.
        param port (int): source port for collection.
    """
    # Capture packets until keyboard interrupt or end of packet stream
    global silentMode
    global target_not_malicious
    global no_fqdn
    global domain_frontable
    global hostOS
    global IFF_PROMISC
    global SIOCSIFFLAGS
    global SIOCGIFFLAGS

    try:
        # Check OS and build socket
        if 'nt' in hostOS:
            host = socket.gethostbyname(host)
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((host, port))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            # Instantiate packet object and buffer
            packet = TargetStructure()
            raw_buffer = s.recvfrom(65565)[0]

            # Extract header from object
            ip_header = raw_buffer[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])

            # Assign fields to packet object
            packet.src = s_addr
            packet.dst = d_addr

            # TCP protocol
            if protocol == 6:
                # Extract TCP header and values
                t = iph_length
                tcp_header = raw_buffer[t:t + 20]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                h_size = iph_length + tcph_length * 4

                # Extract data field
                data_size = len(raw_buffer) - h_size
                data = raw_buffer[h_size:]
                data_str = str(data)

                # Assign fields to packet object
                packet.src_port = source_port
                packet.dst_port
                packet.packet_size = data_size
                packet.data = data_str
                packet.protocol = "TCP"

                # Extract HTTP data
                if "HTTP" in data_str:
                    # print('Data : ' + data_str)
                    if "GET" or "POST" in data_str:
                        http_headers = data_str.split("\\r\\n")
                        url_header = (http_headers[0].split()[1])
                        packet.http_headers = http_headers
                        iter_hdr = iter(http_headers)

                        for header in iter_hdr:
                            if "host" in header.lower():
                                host_hdr = header
                                packet.host_hdr = host_hdr
                        if re.search("\/([a-zA-Z0-9]+)[.]?([a-zA-Z])+|([a-zA-Z/])+", url_header):
                            # print(str(d_addr) + " -> " + url_header)
                            packet.resource = url_header

            # ICMP Packets
            elif protocol == 1:
                # Extract ICMP header and values
                u = iph_length
                icmph_length = 4
                icmp_header = raw_buffer[u:u + 4]
                icmph = struct.unpack('!BBH', icmp_header)
                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]
                h_size = iph_length + icmph_length

                # Extract data field
                data_size = len(raw_buffer) - h_size
                data = raw_buffer[h_size:]

                # Assign fields to packet object
                packet.packet_size = str(data_size)
                packet.data = str(data)
                packet.protocol = "ICMP"

            # UDP packets
            elif protocol == 17:
                # Extract UDP header and values
                u = iph_length
                udph_length = 8
                udp_header = raw_buffer[u:u + 8]
                udph = struct.unpack('!HHHH', udp_header)
                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                # Extract data field
                h_size = iph_length + udph_length
                data_size = len(raw_buffer) - h_size
                data = raw_buffer[h_size:]
                data_str = str(data)

                # Assign fields to packet object
                packet.dst_port = dest_port
                packet.src_port = source_port
                packet.packet_size = data_size
                packet.data = data_str
                packet.protocol = "UDP"

                if "HTTP" in data_str:
                    # Extract HTTP data 
                    if "GET" or "POST" in data_str:
                        http_headers = data_str.split("\\r\\n")
                        url_header = (http_headers[0].split()[1])
                        packet.http_headers = http_headers
                        iter_hdr = iter(http_headers)

                        for header in iter_hdr:
                            if "host" in header.lower():
                                host_hdr = header
                                packet.host_hdr = host_hdr

                        if re.search("\/([a-zA-Z0-9]+)[.]?([a-zA-Z])+|([a-zA-Z/])+", url_header):
                            # print(str(d_addr) + " -> " + url_header)
                            packet.resource = url_header
        # Confirm OS and build socket
        elif "posix" in hostOS:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            errbuf = ctypes.create_string_buffer(init=255)
            dev = libpcap.lookupdev(errbuf)
            host = get_ip_address(dev)
            ifr = ifreq()
            ifr.ifr_ifrn = dev
            fcntl.ioctl(s.fileno(), SIOCGIFFLAGS, ifr)  # G for GET
            ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC
            fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, ifr)  # S for SET

            # Instantiate packet object and buffer
            packet = TargetStructure()
            raw_buffer = s.recvfrom(65565)[0]

            # Extract header data 
            eth_length = 14
            eth_header = raw_buffer[:eth_length]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == 8:
                # Extract IP header and values
                ip_header = raw_buffer[eth_length:20 + eth_length]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF
                iph_length = ihl * 4
                ttl = iph[5]
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])

                # Assign fields to packet object
                packet.src = s_addr
                packet.dst = d_addr

                # TCP protocol
                if protocol == 6:
                    # Extract TCP header and values
                    t = iph_length + eth_length
                    tcp_header = raw_buffer[t:t + 20]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    source_port = tcph[0]
                    dest_port = tcph[1]
                    sequence = tcph[2]
                    acknowledgement = tcph[3]
                    doff_reserved = tcph[4]

                    tcph_length = doff_reserved >> 4
                    h_size = eth_length + iph_length + tcph_length * 4
                    data_size = len(raw_buffer) - h_size
                    data = raw_buffer[h_size:]
                    data_str = str(data)

                    # Assign fields to packet object
                    packet.src_port = source_port
                    packet.dst_port
                    packet.packet_size = data_size
                    packet.data = data_str
                    packet.protocol = "TCP"

                    if "HTTP" in data_str:
                        # Extract HTTP data
                        if "GET" or "POST" in data_str:
                            http_headers = data_str.split("\\r\\n")
                            url_header = (http_headers[0].split()[1])

                            # Assign field to packet object
                            packet.http_headers = http_headers

                            iter_hdr = iter(http_headers)
                            for header in iter_hdr:
                                if "host" in header.lower():
                                    host_hdr = header
                                    packet.host_hdr = host_hdr

                            if re.search("\/([a-zA-Z0-9]+)[.]?([a-zA-Z])+|([a-zA-Z/])+", url_header):
                                # print(str(d_addr) + " -> " + url_header)
                                packet.resource = url_header

                    # ICMP Packets
                elif protocol == 1:
                    # Extract ICMP header and values
                    u = iph_length + eth_length
                    icmph_length = 4
                    icmp_header = raw_buffer[u:u + 4]
                    icmph = struct.unpack('!BBH', icmp_header)
                    icmp_type = icmph[0]
                    code = icmph[1]
                    checksum = icmph[2]

                    h_size = eth_length + iph_length + icmph_length
                    data_size = len(raw_buffer) - h_size
                    data = raw_buffer[h_size:]

                    # Assign fields to packet object 
                    packet.packet_size = str(data_size)
                    packet.data = str(data)
                    packet.protocol = "ICMP"

                # UDP packets
                elif protocol == 17:
                    # Extract UDP header and values
                    u = iph_length + eth_length
                    udph_length = 8
                    udp_header = raw_buffer[u:u + 8]
                    udph = struct.unpack('!HHHH', udp_header)
                    source_port = udph[0]
                    dest_port = udph[1]
                    length = udph[2]
                    checksum = udph[3]

                    h_size = eth_length + iph_length + udph_length
                    data_size = len(raw_buffer) - h_size
                    data = raw_buffer[h_size:]
                    data_str = str(data)

                    # Assign fields to packet object 
                    packet.dst_port = dest_port
                    packet.src_port = source_port
                    packet.packet_size = data_size
                    packet.data = data_str
                    packet.protocol = "UDP"

                    if "HTTP" in data_str:
                        # Extract HTTP data
                        # print('Data : ' + data_str)
                        if "GET" or "POST" in data_str:
                            http_headers = data_str.split("\\r\\n")
                            url_header = (http_headers[0].split()[1])

                            # Assign fields to packet object
                            packet.http_headers = http_headers

                            iter_hdr = iter(http_headers)
                            for header in iter_hdr:
                                if "host" in header.lower():
                                    host_hdr = header
                                    packet.host_hdr = host_hdr

                            if re.search("\/([a-zA-Z0-9]+)[.]?([a-zA-Z])+|([a-zA-Z/])+", url_header):
                                # print(str(d_addr) + " -> " + url_header)
                                packet.resource = url_header

        build_lists(packet)

        if 'nt' in hostOS:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        elif "posix" in hostOS:
            ifr.ifr_flags &= ~IFF_PROMISC
            fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, ifr)
        s.close()

    except KeyboardInterrupt:
        if 'nt' in hostOS:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            return
        elif 'posix' in hostOS:
            ifr.ifr_flags &= ~IFF_PROMISC
            fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, ifr)
            return

    finally:
        s.close()


def runLive():
    """Run live packet analysis."""
    # Capture packets until keyboard interrupt or end of packet stream
    global silentMode

    finished = False
    if silentMode == True:
        blockPrint()

    if 'nt' in hostOS:
        print("\033[1;34;40m Windows Machine")
    elif 'posix' in hostOS:
        print("\033[1;34;40m *nix Machine")

    try:
        while not finished:
            capture_live()
            print("\033[92m Target list_src: " + str(len(targetList_src)), flush=True)
            print("\033[92m Target list_dst: " + str(len(targetList_dst)), flush=True)
            
            find_fqdn()
            print("\033[1;34;40m No FQDN: " + str(len(no_fqdn)), flush=True)
            print("\033[1;34;40m From FQDNs: " + str(len(fqdns)), flush=True)
            make_query_FQDN()
            make_query_no_FQDN()
            

            print("\033[92m Target list_src: " + str(len(targetList_src)), flush=True)
            print("\033[92m Target list_dst: " + str(len(targetList_dst)), flush=True)

            #iter_tl = iter(target_dict.items())
            # for item in iter_tl:
            #    print(item)

            # for fqdn in iter(fqdns):
            #    print(fqdn.domain)
            print("\033[91m Domain frontable: " + str(len(domain_frontable)), flush=True)
            for df in iter(domain_frontable):
                print("[" + str(df.protocol) + "]" + str(df.src) + ":" + str(df.src_port) + " -> " + str(
                    df.dst) + ":" + str(df.dst_port) + "; Domain: " + str(df.domain) + "/" + str(
                    df.resource) + "; Host_Hdr: " + str(df.host_hdr), flush=True)
            print("\033[1;34;40m Not Malicious targets: " + str(len(target_not_malicious)), flush=True)
            print("\033[1;34;40m Query List Size: " + str(len(query_list)) + "\n", flush=True)
            clean_target_dict()

    except KeyboardInterrupt:
        finished = True
        enablePrint()
        print("\033[1;34;40m Capture complete")
        return

    finally:
        enablePrint()
        silentMode = False


def readPackets(pcap_file):
    """Ingest packets from specified PCAP file.
    Args:
        param pcap_file (string): file to be analyzed.
    """
    # Open pcap file and check format
    f = open(pcap_file, 'rb')
    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        pcap = dpkt.pcapng.Reader(f)

    # Iterate through packets and assign values
    for ts, buf in pcap:
        # Instantiate packet object
        packet = TargetStructure()

        try:
            # Extract ethernet header from packet
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue

        # Check if IP header in frame
        # Continue to next packet of not ip packet
        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        try:
            # Exract IP header and fields
            ip = eth.data
            ipLen = ip.len
            ipSrc = inet_to_str(ip.src)
            ipDst = inet_to_str(ip.dst)
            ipProto = ip.p

            # Assign values to packet object
            packet.src = ipSrc
            packet.dst = ipDst
            packet.packet_size = ipLen
            packet.protocol = ipProto
        except:
            pass

        # Check if TCP segment in packet
        if isinstance(ip.data, dpkt.tcp.TCP):

            try:
                # Extract TCP header and fields
                tcp = ip.data
                srcPort = tcp.sport
                dstPort = tcp.dport
                data = tcp.data
                data = data.decode('utf-8')

                # Assign values to packet object
                packet.src_port = srcPort
                packet.dst_port = dstPort
                packet.data = data
                packet.protocol = "TCP"

                try:
                    # Extract HTTP values from tcp segment 
                    httpRequest = dpkt.http.Request(tcp.data)
                    httpHeaders = httpRequest.headers
                    host = httpHeaders.get("host")
                    url = httpRequest.uri

                    # Assign values to packet object
                    packet.http_headers = httpHeaders
                    packet.host_hdr = host
                    packet.resource = url
                except:
                    pass
            except:
                continue

        # Check if UDP segment in packet
        elif isinstance(ip.data, dpkt.udp.UDP):

            try:
                # Extract UDP header and values
                udp = ip.data
                srcPort = udp.sport
                dstPort = udp.dport
                data = udp.data
                data = data.decode('utf-8')

                # Assign values to packet object
                packet.src_port = srcPort
                packet.dst_port = dstPort
                packet.data = data
                packet.protocol = "UDP"

                try:
                    # Extract DNS values from udp segment
                    if dstPort == 53 or srcPort == 53:
                        dns = dpkt.dns.DNS(udp.data)
                        if dns.qr == dpkt.dns.DNS_Q:
                            host = dns.qd[0].name
                        if dns.qr == dpkt.dns.DNS_R:
                            host = dns.an[0].name
                        packet.host_hdr = host
                except:
                    pass
            except:
                continue

        # Check if ICMP segment in packet
        elif isinstance(ip.data, dpkt.icmp.ICMP):
            try:
                # Extract ICMP header and fields
                icmp = ip.data
                data = icmp.data
                data = data.decode('utf-8')

                # Assign values to packet object
                packet.data = icmp.data
                packet.protocol = "ICMP"
                pass
            except:
                continue
        build_lists(packet)

def runPcap(pcap):
    """Run pcap analysis.
    Args:
        param pcap (string): target pcap file.
    """
    # Run pcap processing
    print("\033[1;34;40m Reading pcap and building target list...")
    readPackets(pcap)
    print("\033[1;33;40m Target list_src: " + str(len(targetList_src)))
    print("\033[1;33;40m Target list_dst: " + str(len(targetList_dst)))
    print("\033[1;34;40m Building list of FQDNs from target list...")
    find_fqdn()
    print("\033[1;33;40m No FQDN: " + str(len(no_fqdn)))
    print("\033[1;33;40m From FQDNs: " + str(len(fqdns)))
    print("\033[1;34;40m Identifying domains vulnerable to domain fronting...")
    make_query_FQDN()
    make_query_no_FQDN()
    clean_target_dict()

    print("\033[1;34;40m Domain frontable: " + str(len(domain_frontable)))
    for df in iter(domain_frontable):
        print("[" + str(df.protocol) + "]" + str(df.src) + ":" + str(df.src_port) + " -> " + str(df.dst) + ":" + str(
            df.dst_port) + "; Domain: " + str(df.domain) + "/" + str(df.resource) + "; Host_Hdr: " + str(
            df.host_hdr) + "; Data :" + str(df.data), flush=True)
    print("\033[1;34;40m Not Malicious targets: " + str(len(target_not_malicious)))
    print("\033[1;34;40m Query List Size: " + str(len(query_list)))

    print("\033[1;34;40m Pcap analysis complete")

def iter_check(list, action, source_to_check):
    """Checks for missing data.
    Args:
        param list (list): list to iterate.
        param action (function): function to perform.
        param source_to_check (string): checked value.
    """
    iterator = iter(list)
    done = False

    while not done:
        try:
            for obj in iterator:
                if source_to_check in action(obj):
                    return True
            else:
                done = True
                return False
        except StopIteration:
            done = True
            return False


def get_src(object: TargetStructure):
    """Get source ip from object."""
    return object.src


def get_dst(object: TargetStructure):
    """Get destination ip from object."""
    return object.dst


def put_dictionary(src, dst, data):
    """Puts targets in dictionary.
    Args:
        param src (string): source packet values.
        param dst (string): destination packet values.
        param data (object): packet data.
    """
    global target_dict

    tmp_list = []
    this_entry = {(src, dst): [data]}

    try:
        sentinel_check = target_dict.get((src, dst))
        if sentinel_check:
            iter_sent = iter(sentinel_check)
            for items in iter_sent:
                tmp_list.append(items)

        tmp_list.append(data)
        if sentinel_check:
            update = {(src, dst): tmp_list}
            target_dict.update(update)
        if not sentinel_check:
            target_dict.update(this_entry)
    except KeyError:
        target_dict.update(this_entry)

    except KeyboardInterrupt:
        return


def build_lists(packet: TargetStructure):
    """Iterate through packet and build target list."""
    global targetList_src
    global targetList_dst
    global target_not_malicious
    global fqdns
    global no_fqdn
    global domain_frontable

    src_ip = packet.src
    dst_ip = packet.dst
    try:
        if not iter_check(list=targetList_src, action=get_src, source_to_check=src_ip):
            if not iter_check(list=target_not_malicious, action=get_src, source_to_check=src_ip):
                if not iter_check(list=fqdns, action=get_src, source_to_check=src_ip):
                    if not iter_check(list=no_fqdn, action=get_src, source_to_check=src_ip):
                        if not iter_check(list=domain_frontable, action=get_src, source_to_check=src_ip):
                            targetList_src.append(packet)

        if not iter_check(list=targetList_dst, action=get_dst, source_to_check=dst_ip):
            if not iter_check(list=target_not_malicious, action=get_dst, source_to_check=dst_ip):
                if not iter_check(list=fqdns, action=get_dst, source_to_check=dst_ip):
                    if not iter_check(list=no_fqdn, action=get_dst, source_to_check=dst_ip):
                        if not iter_check(list=domain_frontable, action=get_dst, source_to_check=dst_ip):
                            targetList_dst.append(packet)

        put_dictionary(str(packet.src), str(packet.dst), packet)

    except KeyboardInterrupt:
        return

def find_fqdn():
    """Query fqdns of ips in target lists."""
    global targetList_src
    global targetList_dst
    global target_not_malicious
    global no_fqdn
    global fqdns
    try:
        for target_src in targetList_src:
            try:
                fqdn = socket.gethostbyaddr(target_src.src)[0]
                if fqdn:
                    target_src.domain = fqdn
                    fqdns.append(target_src)
                    targetList_src.remove(target_src)
            except:
                no_fqdn.append(target_src)
                targetList_src.remove(target_src)

        for target_dst in targetList_dst:
            try:
                fqdn = socket.gethostbyaddr(target_dst.dst)[0]
                if fqdn:
                    # print(fqdn)
                    target_dst.domain = fqdn
                    fqdns.append(target_dst)
                    targetList_dst.remove(target_dst)
            except:
                no_fqdn.append(target_dst)
                targetList_dst.remove(target_dst)

    except KeyboardInterrupt:
        return

def get_query(domain, port=80, recv_size=1024, host_hdr=""):
    """Build request parameters.
    Args:
        param domain (string): requested domain.
        param port (int): destination port.
        param recv_size (int): response buffer size.
    Returns:
        response: response data packet.
    """
    global our_domain
    addr = (domain, port)

    if host_hdr:
        # print("Doing host_hdr")
        get = (b"GET / HTTP/1.1\r\n" +
               b"User-Agent: Mozilla/4.0\r\n" +
               b"Host: %s\r\n" % bytes(host_hdr, "utf-8") +
               b"Accepts: */* \r\n\r\n")
    else:
        # print("Doing regular")
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

    except KeyboardInterrupt:
        return

    except:
        if not host_hdr:
            # print("Something went wrong in get_query for " + domain)
            # print()
            pass
        else:
            # print("Somthing went wrong in get_query for " + host_hdr)
            # print()
            pass


def make_query_cdn(domain, host_hdr):
    global enum_list

    reformatted_host_hdr = re.search(r"([.][a-zA-Z]+[.][a-zA-Z]+)", host_hdr)[0]

    for number in enum_list:
        enum_host = (str(number) + str(reformatted_host_hdr))
        try:
            response = get_query(domain=domain, host_hdr=enum_host)
            if "200 OK" in response:
                return response

        except KeyboardInterrupt:
            return

        except:
            # print("Something went wrong in make_query_cdn")
            print()


def make_query_FQDN():
    """Run query against target ip."""
    global target_not_malicious
    global no_fqdn
    global fqdns
    global domain_frontable
    global query_list

    iter_obj = iter(fqdns)

    try:
        for target in iter_obj:
            if not target.host_hdr:
                r = get_query(target.src)
                r_dst = get_query(target.dst)
                if "200 OK" in r:
                    domain_frontable.append(target)
                    fqdns.remove(target)
                    # obtain larger recv from host if 200 OK, full http response
                    r_2 = get_query(target.src, recv_size=65536)
                    query_list.append(r_2)
                    break
                elif "200 OK" in r_dst:
                    domain_frontable.append(target)
                    fqdns.remove(target)
                    # obtain larger recv from host if 200 OK, full http response
                    r_2 = get_query(target.dst, recv_size=65536)
                    query_list.append(r_2)
                    break
                else:
                    target_not_malicious.append(target)
                    fqdns.remove(target)
            else:
                r = make_query_cdn(target.src, host_hdr=target.host_hdr)
                r_dst = make_query_cdn(target.dst, host_hdr=target.host_hdr)
                if r:
                    domain_frontable.append(target)
                    fqdns.remove(target)
                    query_list.append(r)
                    break
                elif r_dst:
                    domain_frontable.append(target)
                    fqdns.remove(target)
                    query_list.append(r_dst)
                    break
                else:
                    target_not_malicious.append(target)
                    fqdns.remove(target)
    except KeyboardInterrupt:
        return

    except:
        target_not_malicious.append(target)
        fqdns.remove(target)


def make_query_no_FQDN():
    """Sends GET request to targets without fqdns."""
    global target_not_malicious
    global no_fqdn
    global domain_frontable
    global query_list

    iter_obj = iter(no_fqdn)

    try:
        for target in iter_obj:
            if not target.host_hdr:
                r_src = get_query(target.src)
                r_dst = get_query(target.dst)
                # print(r_src)
                # print(r_dst)
                if "200 OK" in r_src:
                    domain_frontable.append(target)
                    no_fqdn.remove(target)

                    # obtain larger recv from host if 200 OK, full http response
                    r_2 = get_query(target.src, recv_size=65536)
                    query_list.append(r_2)
                    break
                elif "200 OK" in r_dst:
                    domain_frontable.append(target)
                    no_fqdn.remove(target)

                    # obtain larger recv from host if 200 OK, full http response
                    r_2 = get_query(target.dst, recv_size=65536)
                    query_list.append(r_2)
                    break
                else:
                    target_not_malicious.append(target)
                    no_fqdn.remove(target)
            elif target.host_hdr:
                r_src = get_query(domain=target.src, host_hdr=target.host_hdr)
                r_dst = get_query(domain=target.dst, host_hdr=target.host_hdr)
                if r_src:
                    domain_frontable.append(target)
                    no_fqdn.remove(target)
                    query_list.append(r_src)
                    break
                elif r_dst:
                    domain_frontable.append(target)
                    no_fqdn.remove(target)
                    query_list.append(r_dst)
                    break
                else:
                    target_not_malicious.append(target)
                    no_fqdn.remove(target)

    except KeyboardInterrupt:
        return

    except:
        target_not_malicious.append(target)
        no_fqdn.remove(target)


def clean_target_dict():
    """Clears entry from dictionary."""
    global target_dict
    global target_not_malicious

    try:
        iter_target_not_malicious = iter(target_not_malicious)

        for target in iter_target_not_malicious:
            if target_dict.get((target.src, target.dst)):
                target_dict.pop((target.src, target.dst))

    except KeyboardInterrupt:
        return

    except:
        print("\033[1;31;40m Something went wrong in clean target dict...")
        print()


def write_outfile(output):
    """Converts list to json and prints to output file."""
    global domain_frontable

    # Assign output file
    outFile = output
    
    # Check for extension and replace with .json
    if '.' in outFile:
        stripExt = output.rsplit(".", 1)[0]
    
    # Add json extension
    jsonFile = stripExt + '.json'

    # Writing to text file
    print("\033[1;32;40m Writing results to {}".format(output))
    with open(outFile, 'w') as output:          
        for df in iter(domain_frontable):
            httpData = re.sub(r"\r\n", ", ", df.data)
            output.write("\nPacket: [Protocol:{}] {}:{} -> {}:{}; Domain:{}/{}; Host_hdr:{}; Data:{}".format(
                        str(df.protocol),str(df.src),str(df.src_port),str(df.dst),
                        str(df.dst_port),str(df.domain),str(df.resource),str(df.host_hdr),str(httpData))+"\n")
    output.close()

    # Writing to json file
    print("\033[1;32;40m Writing results to {}".format(jsonFile))

    jsonPackets = {}

    # Iterate through objects and split into keys and values
    outJson = open(jsonFile, 'w')
    for df in iter(domain_frontable):
        httpData = re.sub(r"\r\n", ", ", df.data)
        listKeys = ['Protocol','Src','SrcPort','Dst','DstPort','Domain','Resource','Host','Data']
        listVals = [str(df.protocol),str(df.src),str(df.src_port),str(df.dst),
                    str(df.dst_port),str(df.domain),str(df.resource),str(df.host_hdr),str(httpData)]
        dictPacket = dict(zip(listKeys, listVals))
        jsonPackets['Packet'] = dictPacket    

        json.dump(jsonPackets, outJson, indent=4)
    outJson.close()
       
def inet_to_str(inet):
    """Converts inet object to string.
    Args:
        inet (inet struct): inet network address.
    Returns:
        str: printable/readable IP address.
    """
    # Try IPv4 then IPv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def blockPrint():
    """Redirect stdout and stderr."""
    sys.stdout = open(os.devnull, 'w')
    sys.stderr = open(os.devnull, 'w')


def enablePrint():
    """Restore stdout and stderr to default."""
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__


def flushDNS(command=""):
    """Flush dns cache.
    Args:
        param command (string): DNS flush command.
    """
    global hostOS

    if command:
        try:
            os.system(command)
        except TypeError:
            print("\033[1;31;40m Attempt to flush DNS cache failed. Try default or another command.")
    else:
        try:
            if 'nt' in hostOS:
                print("\033[1;34;40m Attempting: 'ipconfig /flushsns'")
                os.system("ipconfig /flushdns")
            elif 'posix' in hostOS:
                try:
                    # system cache
                    print("\033[1;34;40m Attempting: 'sudo /etc/init.d/dns-clean restart'")
                    os.system("sudo /etc/init.d/dns-clean restart")
                    print("\033[1;34;40m Attempting: 'sudo /etc/init.d/networking force-reload'")
                    os.system("sudo /etc/init.d/networking force-reload")
                    print("\033[1;34;40m Attempting: 'sudo systemd-resolve --flush-caches'")
                    os.system("sudo systemd-resolve --flush-caches")
                    pass
                except TypeError:
                    pass
                try:
                    # nscd DNS cache
                    print("\033[1;34;40m Attempting: 'sudo /etc/init.d/nscd restart'")
                    os.system("sudo /etc/init.d/nscd restart")
                    pass
                except TypeError:
                    pass
                try:
                    # dnsmasq DNS cache
                    print("\033[1;34;40m Attempting: 'sudo /etc/init.d/dnsmasq restart'")
                    os.system("sudo /etc/init.d/dnsmasq restart")
                    pass
                except TypeError:
                    pass
                try:
                    # BIND DNS cache
                    print("\033[1;34;40m Attempting: 'sudo /etc/init.d/named restart'")
                    os.system("sudo /etc/init.d/named restart")
                    print("\033[1;34;40m Attempting: 'sudo rndc restart'")
                    os.system("sudo rndc restart")
                    print("\033[1;34;40m Attempting: 'sudo rndc exec'")
                    os.system("sudo rndc exec")
                    pass
                except TypeError:
                    pass
                try:
                    # Mac mDNSResponder
                    print("\033[1;34;40m Attempting: 'sudo dscacheutil -flushcache'")
                    os.system("sudo dscacheutil -flushcache")
                    print("\033[1;34;40m Attempting: 'sudo killall -HUP mDNSResponder'")
                    os.system("sudo killall -HUP mDNSResponder")
                    pass
                except:
                    pass
                print("\033[1;31;40m Failed to flush DNS cache. Try custom command.")

        except TypeError:
            print("\033[1;31;40m An error occured attempting to flush DNS cache")
            parser.print_help()
            sys.exit(-1)


def has_admin():
    """Check if user is admin or root."""
    if 'posix' in hostOS:
        is_admin = (os.getuid() == 0)
    if 'nt' in hostOS:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_admin


if __name__ == '__main__':

    print("****************************************************")
    print("*                     DFronter                     *")
    print("*              Domain Fronting Detector            *")
    print("*                       v1.0                       *")
    print("****************************************************")

    # Build menu options for live capture and PCAP file
    parser = argparse.ArgumentParser(description='DFronter Detection Tool')
    parser.add_argument('-m', '--mode', choices=['live', 'pcap'], help='Mode of operation')
    parser.add_argument('-p', '--pcap', metavar='pcap file', type=str, help='Pcap file to parse')
    parser.add_argument('-o', '--out', metavar='output file', type=str, help='Specify output file',
                        default="output.txt")
    parser.add_argument('-s', '--silent', help='Run live capture in silent mode', action='store_true')
    parser.add_argument('-f', '--flush', help='Select to flush dns cache.', action='store_true')
    parser.add_argument('-c', '--command', metavar='command to flush dns cache', type=str,
                        help='Provide command to flush dns cache (in quotes).\
                                                 If -=flush selected without command, defaults will be used')
    # Assign flags to variables
    args = parser.parse_args()
    mode = args.mode
    pcap = args.pcap
    output = args.out
    silent = args.silent
    flush = args.flush
    command = args.command

    if has_admin():
        pass
    else:
        print("You must have administrative privileges to run this script.")
        sys.exit()

    # Run live capture in silent mode
    if silent:
        silentMode = True
        print("\033[1;34;40m Running live capture in silent mode.")

    # Check for errors and run dns flush
    if flush:
        try:
            if command:
                print("\033[1;34;40m Running flush command: " + command)
                flushDNS(command)
            else:
                print("\033[1;34;40m Running default flush command.")
                flushDNS()
        except:
            print("\033[1;31;40m The command could not be run.")

    # Run live packet capture
    if mode == 'live':

        try:
            runLive()

            # write_outfile(output)
            if output is not None:
                write_outfile(output)
            else:
                write_outfile(args.out)

        except KeyboardInterrupt:
            exit(0)

    # Check for errors and run pcap analysis
    if mode == 'pcap' and (pcap is None):
        parser.error("\033[1;31;40m [-m,--mode] 'pcap' requires [-p,--pcap] 'file.pcap'")
    if mode == 'pcap':
        if not os.path.isfile(pcap):
            print("\033[1;31;40m {} does not exist".format(pcap), file=sys.stderr)
            sys.exit(-1)
        else:
            runPcap(pcap)

            # write_outfile(output)
            if output is not None:
                write_outfile(output)
            else:
                write_outfile(args.out)

    # Disable silent mode
    silentMode = False
