import random
import select
# import module
import socket
import time

from raw_python import ICMPPacket, IPPacket, parse_icmp_header, parse_ip_header

def calc_rtt(time_sent):
    return time.time() - time_sent

def catch_ping_reply(s, ID, time_sent, timeout=1):
    # create while loop
    while True:
        starting_time = time.time()  # Record Starting Time
        # to handle timeout function of socket
        process = select.select([s], [], [], timeout)
        # check if timeout
        if not process[0]:
            return calc_rtt(time_sent), None, None
        # receive packet
        rec_packet, addr = s.recvfrom(1024)
        icmp_type = rec_packet[20]
        if icmp_type == 11:
            icmp = parse_icmp_header(rec_packet[48:56])
        else:
            icmp = parse_icmp_header(rec_packet[20:28])
        # check identification
        if icmp['id'] == ID:
            icmp['type'] = icmp_type
            return calc_rtt(time_sent), parse_ip_header(rec_packet[:20]), icmp

def single_ping_request(s, _ttl, addr=None):
    # Random Packet Id
    pkt_id = random.randrange(10000, 65000)
    # Create IP Header
    ip_header = IPPacket(dst=addr, ttl=_ttl).raw
    # Create ICMP Packet
    icmp_packet = ICMPPacket(_id=pkt_id).raw
    # Combine into whole packet
    packet = ip_header +icmp_packet
    # Send ICMP Packet
    while packet:
        sent = s.sendto(packet, (addr, 1))
        packet = packet[sent:]
    return pkt_id

def main():
    # create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # take Input
    addr = input("[+] Enter Domain Name : ") or "www.sustc.edu.cn"
    print('TRACEROUTE {0} ({1}) 56(84) bytes of data.'.format(addr, socket.gethostbyname(addr)))
    addr = socket.gethostbyname(addr)
    print('{0:^8s}{1:^20s}{2:^10s}{3:^8s}{4:^8s}{5:^8s}'.format('Index', 'Address', 'Loss', 'Ave/ms', 'Max/ms', 'Min/ms'))
    #Request sent
    ttl = 1
    reach = False
    while not reach and ttl <= 255:
        rtt_list = []
        dest_loc = None
        for i in range(3):
            ID = single_ping_request(s, ttl, addr)
            rtt, reply, icmp_reply = catch_ping_reply(s, ID, time.time())
            if not reply is None:
                dest_loc = reply["Source Address"]
                rtt_list.append(rtt * 1000)
                reach = True if icmp_reply['type'] == 0 else False
        if dest_loc is None:
            print('{0:^8}{1:^20s}{2:^10.1%}{3:^8s}{4:^8s}{5:^8s}'.format(ttl, '*', 1, '*', '*', '*'))
        else:
            ave = 0
            max = 0
            min = 1000
            loss = (3 - rtt_list.__len__())/3
            for i in rtt_list:
                ave += i
                max = i  if i >= max else max
                min = i  if i <= min else min
            ave /= rtt_list.__len__()
            print('{0:^8}{1:^20s}{2:^10.1%}{3:^8.2f}{4:^8.2f}{5:^8.2f}'.format(ttl, dest_loc, loss, ave, max, min))
        ttl += 1

    if reach:
        print("Traceroute Complete!")
    else:
        print("Traceroute Fail!")

    # close socket
    s.close()
    return

if __name__ == '__main__':
    main()