import socket
import struct
import textwrap

# Function to unpack Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Function to format MAC address (AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Function to unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Function to format IPv4 address (192.168.1.1)
def ipv4(addr):
    return '.'.join(map(str, addr))

# Main function to capture and analyze network packets
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}')

        # IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print('\nIPv4 Packet:')
            print(f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'Protocol: {proto}, Source: {src}, Target: {target}')

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = struct.unpack('! B B H', data[:4])
                print('\nICMP Packet:')
                print(f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print('Data:')
                print(textwrap.indent(textwrap.fill(repr(data), width=50), '  '))
                
            # TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
                offset = (offset_reserved_flags >> 12) * 4
                flags = offset_reserved_flags & 0x1FF
                print('\nTCP Segment:')
                print(f'Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print('Flags:')
                print(f'URG: {(flags & 0x20) >> 5}, ACK: {(flags & 0x10) >> 4}, PSH: {(flags & 0x8) >> 3}, RST: {(flags & 0x4) >> 2}, SYN: {(flags & 0x2) >> 1}, FIN: {flags & 0x1}')
                print('Data:')
                print(textwrap.indent(textwrap.fill(repr(data[offset:]), width=50), '  '))
            
            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = struct.unpack('! H H H', data[:8])
                print('\nUDP Segment:')
                print(f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                print('Data:')
                print(textwrap.indent(textwrap.fill(repr(data), width=50), '  '))
            
            # Other IPv4
            else:
                print('\nOther IPv4 Data:')
                print(textwrap.indent(textwrap.fill(repr(data), width=50), '  '))

        # Other Ethernet
        else:
            print('\nOther Ethernet Data:')
            print(textwrap.indent(textwrap.fill(repr(data), width=50), '  '))

if __name__ == "__main__":
    main()
