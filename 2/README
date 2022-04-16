# IPK 2. project - ethernet packet sniffer
## Brief description
C++/C program implementing Ethernet packet sniffer.\
Utilises libraries **pcap.h** for packet capturing, **netinet/*.h** for convinient packet type-casting.

Program supports different options for packet sniffing. Such as filtering dependent on packet type or port number, and packet number limitation.
### Supported traffic:
- IPv4:
  - TCP
  - UDP
  - ICMP
- IPv6:
  - TCP
  - UDP
  - ICMPv6
- ARP
## Usage
### Building
- make all (gcc -o ipk-sniffer *.cpp -l pcap)
### Execution

#### 0. Get information about available interfaces
```
$./ipk-sniffer -i
```
Result:
```
Interfaces available:
1. eno1
2. wlo1
3. any
4. lo
5. bluetooth0
6. bluetooth-monitor
7. nflog
8. nfqueue
9. dbus-system
10. dbus-session
```

#### 1. Capture 2 ARP packets
```
$./ipk-sniffer -i eno1 -n 2 --arp
```
Result:
```
Sniffing started with filter "arp"

Packet #1
timestamp: 2022-04-16T12:57:28.751+02:00
src MAC: 94:3f:c2:07:ca:1a
dst MAC: ff:ff:ff:ff:ff:ff
frame length: 60
ether type: ARP
src IP: 147.229.212.1
dst IP: 147.229.213.242
0x0000:  ff ff ff ff ff ff 94 3f  c2 07 ca 1a 08 06 00 01  .......? ........
0x0010:  08 00 06 04 00 01 94 3f  c2 07 ca 1a 93 e5 d4 01  .......? ........
0x0020:  00 00 00 00 00 00 93 e5  d5 f2 00 00 00 00 00 00  ........ ........
0x0030:  00 00 00 00 00 00 00 00  00 00 00 00              ........ ....

Packet #2
timestamp: 2022-04-16T12:57:28.755+02:00
src MAC: 94:3f:c2:07:ca:1a
dst MAC: ff:ff:ff:ff:ff:ff
frame length: 60
ether type: ARP
src IP: 147.229.212.1
dst IP: 147.229.214.130
0x0000:  ff ff ff ff ff ff 94 3f  c2 07 ca 1a 08 06 00 01  .......? ........
0x0010:  08 00 06 04 00 01 94 3f  c2 07 ca 1a 93 e5 d4 01  .......? ........
0x0020:  00 00 00 00 00 00 93 e5  d6 82 00 00 00 00 00 00  ........ ........
0x0030:  00 00 00 00 00 00 00 00  00 00 00 00              ........ ....
```
#### 2. Capture 2 either UDP or TCP packets
```
$./ipk-sniffer -i eno1 -n 2 --udp --tcp
```
Result:
```
Sniffing started with filter "udp or tcp"

Packet #1
timestamp: 2022-04-16T13:00:46.526+02:00
src MAC: 70:85:c2:51:17:97
dst MAC: 33:33:00:01:00:02
frame length: 128
ether type: IPv6
src IP: fe80::7285:c2ff:fe51:1797
dst IP: ff02::1:2
protocol: UDP
src port: 546
dst port: 547
0x0000:  33 33 00 01 00 02 70 85  c2 51 17 97 86 dd 60 00  33....p. .Q....`.
0x0010:  00 00 00 4a 11 40 fe 80  00 00 00 00 00 00 72 85  ...J.@.. ......r.
0x0020:  c2 ff fe 51 17 97 ff 02  00 00 00 00 00 00 00 00  ...Q.... ........
0x0030:  00 00 00 01 00 02 02 22  02 23 00 4a 12 bb 01 33  ......." .#.J...3
0x0040:  ca 0f 00 01 00 0e 00 01  00 01 29 ed 5e 56 70 85  ........ ..).^Vp.
0x0050:  c2 51 17 97 00 03 00 0c  00 05 7f 16 00 00 00 00  .Q...... ........
0x0060:  00 00 00 00 00 08 00 02  02 cd 00 06 00 02 00 17  ........ ........
0x0070:  00 19 00 0c 00 05 7f 15  00 00 00 00 00 00 00 00  ........ ........

Packet #2
timestamp: 2022-04-16T13:00:46.556+02:00
src MAC: 94:3f:c2:07:ca:1a
dst MAC: b0:0c:d1:64:0a:c1
frame length: 105
ether type: IPv4
src IP: 157.240.30.18
dst IP: 147.229.212.31
protocol: TCP
src port: 443
dst port: 42528
0x0000:  b0 0c d1 64 0a c1 94 3f  c2 07 ca 1a 08 00 45 00  ...d...? ......E.
0x0010:  00 5b 96 72 40 00 58 06  68 23 9d f0 1e 12 93 e5  .[.r@.X. h#......
0x0020:  d4 1f 01 bb a6 20 a7 cf  63 99 61 1d 00 14 80 19  ..... .. c.a.....
0x0030:  01 27 bc 40 00 00 01 01  08 0a e8 65 f6 43 34 b0  .'.@.... ...e.C4.
0x0040:  7d e1 17 03 03 00 22 55  59 0c 86 b8 3a 37 bc fa  }....."U Y...:7..
0x0050:  59 6f 13 bd cb 54 bc 85  f0 5f 3f 7e 96 ba a3 94  Yo...T.. ._?~....
0x0060:  fd d2 4c ca 0c 3a 8b 11  9b                       ..L..:.. .
```
#### 3. Capture single packet from port 80
```
$./ipk-sniffer -i eno1 -p 80
```
Result:
```
Sniffing started with filter "port 80"

Packet #1
timestamp: 2022-04-16T13:03:15.316+02:00
src MAC: b0:0c:d1:64:0a:c1
dst MAC: 94:3f:c2:07:ca:1a
frame length: 74
ether type: IPv4
src IP: 147.229.212.31
dst IP: 35.224.170.84
protocol: TCP
src port: 34074
dst port: 80
0x0000:  94 3f c2 07 ca 1a b0 0c  d1 64 0a c1 08 00 45 00  .?...... .d....E.
0x0010:  00 3c d5 93 40 00 40 06  2e ef 93 e5 d4 1f 23 e0  .<..@.@. ......#.
0x0020:  aa 54 85 1a 00 50 f4 28  45 51 00 00 00 00 a0 02  .T...P.( EQ......
0x0030:  fa f0 36 68 00 00 02 04  05 b4 04 02 08 0a 08 26  ..6h.... .......&
0x0040:  5c 6d 00 00 00 00 01 03  03 07                    \m...... ..

```
## List of files
- Makefile
- sniffer.hpp
- sniffer.cpp
- main.cpp
- manual.pdf
- README.md