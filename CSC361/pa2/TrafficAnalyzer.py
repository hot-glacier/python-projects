import sys
import struct
import socket
from statistics import mean

#Definition of formats and global variables

Global_Header_Format = 'IHHiIII'
Packet_Header_Format = 'IIII'
Ethernet_Header_Len = 14    #bytes
IP_Header_Min = 20          #bytes
TCP_Header_Min = 20         #bytes
Ethernet_IP = 0x0800
IP_Protocol_TCP = 6
FIRST_TIMESTAMP = None

#Define TCP flag values
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10

class Connection:
    def __init__(self, key):
        self.key = key  # (source, source port, destination, destination port)
        self.start_time = None
        self.end_time = None
        self.syn_count = 0
        self.fin_count = 0
        self.rst = False
        self.packets_fwd = 0
        self.packets_rev = 0
        self.bytes_fwd = 0
        self.bytes_rev = 0
        self.rtts = []
        #First SYN time used for calculating RTT
        self.syn_time = None 
        #SEQ number of the first SYN for calculating RTT
        self.initial_syn_seq = None
        self.window_sizes = []

    def update(self, ts, direction, tcp_flags, tcp_len, seq=None, ack=None, window=None):
        temp_end_time = self.end_time   #Stored in case reset packet
        if self.start_time is None:
            self.start_time = ts
        self.end_time = ts

        #SYN/FIN/RST tracking
        is_syn = (tcp_flags & TCP_SYN)
        is_ack = (tcp_flags & TCP_ACK)

        if is_syn:
            self.syn_count += 1
            if direction == 'fwd' and self.syn_time is None:    #Initial SYN (for RTT calculation)
                self.syn_time = ts
                self.initial_syn_seq = seq
        
        #Calculate RTT when SYN-ACK is seen
        if direction == 'rev' and is_syn and is_ack and self.syn_time is not None:
            #Check if SYN-ACK is acknowledging the initial SYN (ack = initial_syn_seq + 1)
            if ack == self.initial_syn_seq + 1: 
                 rtt = ts - self.syn_time
                 self.rtts.append(rtt)
                 self.syn_time = None #Reset syn_time to ensure RTT is only calculated once per initial SYN

        if tcp_flags & TCP_FIN:  #FIN flag
            self.fin_count += 1
            #self.end_time = temp_end_time
        if tcp_flags & TCP_RST:  #RST flag
            self.rst = True
            self.end_time = temp_end_time   #If reset, do not update end time

        #Counting forward and reverse packets
        if direction == 'fwd':
            self.packets_fwd += 1
            self.bytes_fwd += tcp_len
        else:
            self.packets_rev += 1
            self.bytes_rev += tcp_len

        self.window_sizes.append(window)

    def state(self):
        if self.rst:
            return "RESET"
        elif self.is_complete():
            return "COMPLETE"
        elif self.syn_count >= 1 and self.fin_count == 0:
            return "OPEN"
        elif self.syn_count == 0:
            return "ESTABLISHED BEFORE CAPTURE"
        return "UNKNOWN"

    def is_complete(self):
        return self.syn_count >= 1 and self.fin_count >= 1

    def duration(self):
        return self.end_time - self.start_time

    def total_packets(self):
        return self.packets_fwd + self.packets_rev

    def total_bytes(self):
        return self.bytes_fwd + self.bytes_rev

def read_packets(filename):
    # This function reads packets from a .cap file
    global FIRST_TIMESTAMP
    f = open(filename, 'rb')
    global_header = f.read(24)
    magic_number = struct.unpack('I', global_header[:4])[0]
    endianness = '<' if magic_number == 0xa1b2c3d4 else '>'
    Packet_Header_Format_End = endianness + Packet_Header_Format

    while True:
        Header = f.read(16) #Read packet header
        if not Header:
            break
        if len(Header) < 16:
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(Packet_Header_Format_End, Header)
        Data = f.read(incl_len)
        absolute_ts = ts_sec + ts_usec / 1e6
        if FIRST_TIMESTAMP is None:     #Determine the first timestamp for relative time calculation
            FIRST_TIMESTAMP = absolute_ts
            relative_ts = 0.0
        else:
            relative_ts = absolute_ts - FIRST_TIMESTAMP
        yield (relative_ts, Data)    #Returns timestamp and packet data

def parse_ethernet(Data):
    #Parse the ethernet header and return the ethernet type and data
    if len(Data) < Ethernet_Header_Len: #Ethernet Header must be 14 bytes
        return None, None
    Ethernet_Header = struct.unpack('!6s6sH', Data[:Ethernet_Header_Len]) #Header is the first 14 bytes
    Ethernet_Type = Ethernet_Header[2] #Type is after Destination MAC Address and Source MAC Address
    return Ethernet_Type, Data[Ethernet_Header_Len:]


def parse_ip(IP_Data):
    #Parse the IPv4 header and return the source, destination, protocol, and data
    if len(IP_Data) < IP_Header_Min: #IP Header must be 20 bytes, at least
        return None
    IP_Version = IP_Data[0]
    IHL = (IP_Version & 0xF) * 4    #First 4 bits are IP_Version, last 4 are IHL; isolate and convert last 4 bits to bytes
    IPH = struct.unpack('!BBHHHBBH4s4s', IP_Data[:20]) #Unpack first 20 bytes to get the IP Header (network byte order)
    protocol = IPH[6]   #Extract protocol, length, src_ip, and dst_ip, converting the IPs to regular IP format
    total_len = IPH[2]
    src_ip = socket.inet_ntoa(IPH[8])
    dst_ip = socket.inet_ntoa(IPH[9])
    return src_ip, dst_ip, protocol, IP_Data[IHL:total_len]


def parse_tcp(TCP_Data):
    #Parse the TCP header and return relevant fields and data
    if len(TCP_Data) < TCP_Header_Min:  #TCP Header must be at least 20 bytes
        return None
    TCP_Header = struct.unpack('!HHLLBBHHH', TCP_Data[:20])   #Unpack the 20 byte header
    src_port, dst_port, seq, ack_seq, offset_res, flags, window, check, urg_ptr = TCP_Header    #Extract header fields
    offset = (offset_res >> 4) * 4  #Isolate offset value by shifting byte 4 bits over, then convert to bytes
    Data = TCP_Data[offset:]    #Isolate segment data
    return {    #Return fields needed to track TCP Connections
        'src_port': src_port,
        'dst_port': dst_port,
        'seq': seq,
        'ack_seq': ack_seq,
        'flags': flags,
        'window': window,
        'data_len': len(Data)
    }


#Parse the passed in file through Ethernet, IP, and TCP layers to extract packets, skipping any packets that are not TCP packets
def parse_file(filename):
    connections = {}        #Dictionary to hold all TCP connections
    for ts, Packet_Data in read_packets(filename):
        Ethernet_Type, Data = parse_ethernet(Packet_Data)   #Parse the Ethernet header segment
        if Ethernet_Type != Ethernet_IP:    #Skip if the packet is not an IPv4 packet
            continue
        parsed_IP = parse_ip(Data)  #Parse the IP header segment
        if not parsed_IP:
            continue
        src_ip, dst_ip, protocol, TCP_Data = parsed_IP
        if protocol != IP_Protocol_TCP: #Checks if the packet is TCP, skip if not
            continue

        TCP = parse_tcp(TCP_Data)   #Parse the TCP segment and its data
        if not TCP:
            continue

        src_port, dst_port = TCP['src_port'], TCP['dst_port']   #Determine the source and destination IP/ports
        fwd_tuple = (src_ip, src_port, dst_ip, dst_port)        #Source -> Destination implies forward
        rev_tuple = (dst_ip, dst_port, src_ip, src_port)        #vice versa


        #This section determines which connection a packet belongs to, using the fwd/rev keys created above
        if fwd_tuple in connections:        #Existing forward connection direction
            conn = connections[fwd_tuple]
            direction = 'fwd'
        elif rev_tuple in connections:      #Existing reverse connection direction
            conn = connections[rev_tuple]
            direction = 'rev'
        else:                               #New forward connection
            conn = Connection(fwd_tuple)
            connections[fwd_tuple] = conn
            direction = 'fwd'

        conn.update(            #Update connection data, including the necessary TCP fields for RTT
            ts, 
            direction, 
            TCP['flags'], 
            TCP['data_len'], 
            seq=TCP['seq'], 
            ack=TCP['ack_seq'], 
            window=TCP['window']
        )

    # Print out the required results sections A-D
    
    print("A) Total number of connections:", len(connections))  #Print the results of A)
    print("\nB) Connections' details:")     #Iterate through all connections and print the results of B)

    for i, conn in enumerate(connections.values(), 1):
        src, sport, dst, dport = conn.key
        print(f"Connection {i}:")
        print(f"Source Address: {src}")
        print(f"Destination Address: {dst}")
        print(f"Source Port: {sport}")
        print(f"Destination Port: {dport}")
        print(f"Status: {conn.state()}")

        if conn.is_complete():  #Details for connections that were completed (reset or not)
            print(f"Start Time: {conn.start_time:.6f} s")   #Use 6 digits after decimal
            print(f"End Time: {conn.end_time:.6f} s")
            print(f"Duration: {conn.duration():.6f} s")
            print(f"Number of packets sent from Source to Destination: {conn.packets_fwd}")
            print(f"Number of packets sent from Destination to Source: {conn.packets_rev}")
            print(f"Total number of packets: {conn.total_packets()}")
            print(f"Number of data bytes sent from Source to Destination: {conn.bytes_fwd}")
            print(f"Number of data bytes sent from Destination to Source: {conn.bytes_rev}")
            print(f"Total number of data bytes: {conn.total_bytes()}")
        print("END\n")

    #Variables for part C)
    complete = [c for c in connections.values() if c.is_complete()]
    resets = [c for c in connections.values() if c.rst]
    still_open = [c for c in connections.values() if not c.is_complete() and c.syn_count >= 1]    #Still open means the connection is not complete and has seen at least 1 SYN
    established_before = [c for c in connections.values() if c.syn_count == 0]      #If there are no SYN's, but the connection has other flags set, the connection was open prior to trace capture

    print("C) General")     #Print the results of C)
    print(f"The total number of complete TCP connections: {len(complete)}")
    print(f"The number of reset TCP connections: {len(resets)}")
    print(f"The number of TCP connections that were still open when the trace capture ended: {len(still_open)}")
    print(f"The number of TCP connections established before the capture started: {len(established_before)}")

    print("\nD) Complete TCP connections:")     #Print the results of D
    if complete:
        #Variables for part D)
        durations = [c.duration() for c in complete]    #Durations (time from first packet to last packet) for all complete connections
        all_windows = [w for c in complete for w in c.window_sizes]
        windows = all_windows if all_windows else [0]
        packets = [c.total_packets() for c in complete]     #Total packets for each connection
        rtts = [r for c in complete for r in c.rtts if c.rtts] or [0] #Only include RTTs that were actually calculated (list is not empty)

        print(f"Minimum time duration: {min(durations):.6f} s")
        print(f"Mean time duration: {mean(durations):.6f} s")
        print(f"Maximum time duration: {max(durations):.6f} s")

        print(f"Minimum RTT value: {min(rtts):.6f} s")
        print(f"Mean RTT value: {mean(rtts):.6f} s")
        print(f"Maximum RTT value: {max(rtts):.6f} s")

        print(f"Minimum number of packets including both send/received: {min(packets)}")
        print(f"Mean number of packets including both send/received: {mean(packets):.6f}")
        print(f"Maximum number of packets including both send/received: {max(packets)}")

        print(f"Minimum receive window size including both send/received: {min(windows)} bytes")
        print(f"Mean receive window size including both send/received: {mean(windows):.6f} bytes")
        print(f"Maximum receive window size including both send/received: {max(windows)} bytes")
    else:
        print("No complete connections found.")
    


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Incorrect syntax: Enter command as \"python3 TrafficAnalyzer.py <file_name>\"")
        exit()
    filename = sys.argv[1]
    parse_file(filename)
    