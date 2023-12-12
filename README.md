# arpspoof - 윈도우용 ARP Spoofing 프로그램

이 프로그램은 `고려대학교 세종캠퍼스 2023 통신및네트워크 수업 과제`로 작성한 프로그램으로, [alandau/arpspoof](https://github.com/alandau/arpspoof) 코드에 기반한 C++ 버전의 단일 Host에 대한 ARP Spoofing 프로그램과, [「python을 이용한 ARP 스푸핑 구현하기 by 웹하는빡통」](https://webstone.tistory.com/107) 코드에 기반한 단일/다중 Host에 대한 python 버전의 ARP Spoofing 프로그램입니다.

이하 문서에서는 `python 버전의 코드`를 소개하고자 합니다. C++ 프로그램에 대한 설명은 해당 폴더 내 마크다운 문서를 확인하기 바랍니다.

### 요약

```
> python ./arpspoof.py 192.168.0.1 192.168.0.10
ARP Spoofing 시작 -> VICTIM IP [{192.168.0.10}]
[{192.168.0.10}]: POISON ARP Table [{11:22:33:44:55:66}] -> [{77:88:99:aa:bb:cc}]
Ctrl + C를 누르면 ARP Spoofing을 종료합니다.
```

### 설치

프로그램을 사용하기 위해서는 `scapy` 모듈이 필요합니다.

```
> pip install scapy
```

이후 [Releases](https://github.com/geolee1/KUS_arpspoof_2023/releases)에서 `arpspoof.py`를 저장 후 cli 환경에서 실행합니다.

```
> python ./arpspoof.py [options] [<args>]
```

### 사용법

```
> python ./arpspoof.py --help
ARP Spoofing Program 1.0.0

usage: ./arpspoof.py [options] [<args>]

Options:
   <gateway ip> <target ip 1> [<target ip 2> ..]   ARP Spoofing
   -n --network <gateway ip> <network CIDR>        ARP Spoofing for all network targets
   -h --help                                       Show this help message
```

- 프로그램 인자로 `옵션을 주지 않으면` 타겟 ip들에 대해 gateway ip로 위장하여 스푸핑을 진행합니다.
- `-n` 혹은 `--network` 옵션을 주면, 네트워크 CIDR에 대하여 ping을 통해 Live Host를 찾고, 찾은 ip에 스푸핑을 진행합니다.
- `-h` 혹은 `--help` 옵션은 도움말을 출력합니다.

### 주의사항

스푸핑은 불법 사항이므로 개인 네트워크 망에서만 사용하길 바랍니다. 이 프로그램을 사용하므로 생긴 피해는 책임지지 않습니다.
