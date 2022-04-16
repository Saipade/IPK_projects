/**
 * @file sniffer.cpp
 * @author Maksim Tikhonov (xtikho00)
 * @brief Implementation of Sniffer class methods
 * 
 */

#include "sniffer.hpp"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <typeinfo>
#include <cstring>
#include <bitset> 
#include <math.h>
#include <time.h>


#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>


using namespace std;

/**
 * @brief Packet handler function;
 * P.S. pcap_loop doesn't accept class' method as an argument
 * 
 * @param packetCounter counter for packets' enumeration
 * @param header information about the packet (time stamp, length of portion present, length of packet)
 * @param packet packet itself, sequence of bytes
 */
void packetHandler(u_char* packetCounter, const struct pcap_pkthdr* header, const u_char* packet);

void Sniffer::parseArguments(int argc, char* argv[]) {
    char c;
    while ((c = getopt_long(argc, argv, shortOptions, longOptions, nullptr)) != -1) {
        switch (c) {
            case 'i':
                if (optarg == NULL and optind < argc and argv[optind][0] != '-')
                    optarg = argv[optind++];

                if (optarg == NULL) {
                    printInterfaces();
                    exit(0);
                }
                else {
                    interface.assign(optarg);
                }
            break;
            case 'p':
                port.append("port ");       
                port.append(optarg); // so the port part of the filter expression will be "port <N>"
            break;
            case 't':
                (udp and icmp and arp) ? (udp = false, icmp = false, arp = false) : 0;
                tcp = true;
                filter.append("tcp or ");
            break;
            case 'u':
                (tcp and icmp and arp) ? (tcp = false, icmp = false, arp = false) : 0;
                udp = true;
                filter.append("udp or ");
            break;
            case 'n':
                packetNumber = stoi(optarg);
            break;
            case 'a':
                (tcp and udp and icmp) ? (tcp = false, udp = false, icmp = false) : 0;
                arp = true;
                filter.append("arp or ");
            break;
            case 'c':
                (tcp and udp and arp) ? (tcp = false, udp = false, arp = false) : 0;
                filter.append("icmp or icmp6 or ");
            break;
            case 'h':
                if (argc != 2) // -h is incompatible with other options
                    exit(1);
            case '?':
            default:
                printHelp();
                exit(0);
            break;
        }
    }
    /* remove last "or " and concatenate filter and port */
    filter = filter.substr(0, filter.length() - 4);
    port.empty() ? filter = filter : (filter.empty() ? filter = port: filter = filter + " and " + port);
}

void Sniffer::openDevice() {
    /* Initialise the library */
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf) == PCAP_ERROR) {
        printf("Pcap initialisation failed\nError: %s\n", errbuf);
        exit(1);
    }

    /* If there is no interface given -> find first available */
    if (interface.empty()) { // pcap_lookupdev is obsoleted by pcap_findalldevs :-D
        pcap_if_t* allDevs;
        if (pcap_findalldevs(&allDevs, errbuf) == PCAP_ERROR) {
            printf("No interfaces found\nError: %s\n", errbuf);
            exit(1);
        }
        interface.assign(allDevs->name); // get the name of the first device available
        pcap_freealldevs(allDevs);
    }

    /* Look up net for mask */
    bpf_u_int32 notUsed;
    bpf_u_int32 net;
    if (pcap_lookupnet(interface.c_str(), &net, &notUsed, errbuf) == PCAP_ERROR) {
        printf("Can't get a net mask for the device \"%s\"\nError: %s\n", interface.c_str(), errbuf);
        exit(1);
    }

    /* Open device */
    if ((handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf)) == NULL) {
        printf("Couldn't open the device \"%s\"\nError: %s\n", interface.c_str(), errbuf);
        exit(1);
    }

    /* Compile a filter expression */
    struct bpf_program filterExpression;
    if (pcap_compile(handle, &filterExpression, filter.c_str(), 0, net) == PCAP_ERROR) {
        printf("Couldn't compile the filter expression \"%s\"\nError: %s\n", filter.c_str(), pcap_geterr(handle));
        exit(1);
    }

    /* Set filter */
    if (pcap_setfilter(handle, &filterExpression) == PCAP_ERROR) {
        printf("Couldn't set the filter \"%s\"\nError: %s\n", filter.c_str(), pcap_geterr(handle));
        exit(1);
    }
}

void Sniffer::sniff() {
    filter.empty() ? printf("Sniffing started with no filter\n") :printf("Sniffing started with filter \"%s\"\n", filter.c_str());
    if (pcap_loop(handle, packetNumber, packetHandler, &packetCounter) <= -1) {
        printf("Sniffing error occured\n");
    }
    /* Close pcap handle */
    pcap_close(handle);
}

void packetHandler(u_char* packetCounter, const struct pcap_pkthdr* header, const u_char* packet) {
    (*packetCounter == 0) ? *packetCounter = *packetCounter + 1 : *packetCounter = *packetCounter;
    /* Obtain basic info */
    int packetLength = header->len; // length of this packet
    int frameLength = header->caplen; // length of portion present
    struct ether_header* ethHeader = (struct ether_header*) packet;
    int headerOffset = sizeof(struct ether_header); // offset that determines how many bytes are passed
    uint16_t srcPort, dstPort;

    /* Deal with time */
    char timeBuffer[20];
    char timezoneBuffer[6];
    struct tm* timeInfo = localtime(&header->ts.tv_sec); 
    strftime(timeBuffer, sizeof(timeBuffer), "%FT%T", timeInfo); // <date>T<time>
    int milliseconds = lrint(header->ts.tv_usec / 1000.0); // round to nearest millisecond
    strftime(timezoneBuffer, sizeof(timezoneBuffer), "%z", timeInfo); // timezone
    // converting timezone offset to RFC3339 format
    string timezone = timezoneBuffer; // e.g. +300 to +03:00, +1000 to +10:00
    (timezone.length() == 4) ? (timezone.insert(1, 1, '0'), timezone.insert(3, 1, ':')) : (timezone.insert(3, 1, ':'));
    
    /* Deal with MAC addresses */
    char srcMAC[MAC_LEN], dstMAC[MAC_LEN];
    sprintf(srcMAC, "%02x:%02x:%02x:%02x:%02x:%02x", *ethHeader->ether_shost, *(ethHeader->ether_shost + 1), *(ethHeader->ether_shost + 2),
    *(ethHeader->ether_shost + 3), *(ethHeader->ether_shost + 4), *(ethHeader->ether_shost + 5));
    sprintf(dstMAC, "%02x:%02x:%02x:%02x:%02x:%02x", *ethHeader->ether_dhost, *(ethHeader->ether_dhost + 1), *(ethHeader->ether_dhost + 2),
    *(ethHeader->ether_dhost + 3), *(ethHeader->ether_dhost + 4), *(ethHeader->ether_dhost + 5));

    /* Print info we can extract from given frame */
    printf(
        "\n"
        "Packet #%d\n"
        "timestamp: %s.%03d%s\n"
        "src MAC: %s\n"
        "dst MAC: %s\n"
        "frame length: %i\n", *packetCounter, timeBuffer, milliseconds, timezone.c_str(), srcMAC, dstMAC, frameLength);

    /* Switch on ether type */
    switch (ntohs(ethHeader->ether_type)) {
        /* IPv4 ether type */
        case ETHERTYPE_IP: {
            struct ip* IPv4Header = (struct ip*) (packet + headerOffset);
            /* Get source and destination addresses, update header offset */
            char srcIPv4[INET_ADDRSTRLEN];
            char dstIPv4[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &IPv4Header->ip_src, srcIPv4, INET_ADDRSTRLEN);
		    inet_ntop(AF_INET, &IPv4Header->ip_dst, dstIPv4, INET_ADDRSTRLEN);
            headerOffset += sizeof(struct ip); 
            /* Print ether type, src/dst IPs */
            printf(
                "ether type: IPv4\n"
                "src IP: %s\n"
                "dst IP: %s\n", srcIPv4, dstIPv4);
            /* Switch on IPv4's protocol */
            switch (IPv4Header->ip_p) {
                /* TCP */
                case IPPROTO_TCP: {
                    struct tcphdr* tcpHeader = (struct tcphdr*) (packet + headerOffset);
                    /* Obtain source and destination ports */
                    srcPort = ntohs(tcpHeader->source);
                    dstPort = ntohs(tcpHeader->dest);
                    headerOffset += tcpHeader->doff*4;
                    printf("protocol: TCP\n");
                } break;

                /* UDP */
                case IPPROTO_UDP: {
                    struct udphdr* udpHeader = (struct udphdr*) (packet + headerOffset);
                    /* Obtain source and destination ports */
                    srcPort = ntohs(udpHeader->source);
                    dstPort = ntohs(udpHeader->dest);
                    headerOffset += sizeof(struct udphdr);
                    printf("protocol: UDP\n");
                } break;

                /* ICMP */
                case IPPROTO_ICMP: {
                    struct icmphdr* icmpHeader = (struct icmphdr*) (packet + headerOffset);
                    headerOffset += sizeof(icmpHeader);
                    printf("Prototcol: ICMPv4\n");
                } break;
            }

            /* Print src/dst ports (if there are ports) */
            if (IPv4Header->ip_p != IPPROTO_ICMP)
                printf(
                    "src port: %d\n"
                    "dst port: %d\n", srcPort, dstPort);

        } break;


        /* IPv6 ether type */
        case ETHERTYPE_IPV6: {
            struct ip6_hdr* IPv6Header = (struct ip6_hdr*) (packet + headerOffset);
            /* Get source and destination addresses update header offset */
            char srcIPv6[INET6_ADDRSTRLEN];
            char dstIPv6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &IPv6Header->ip6_src, srcIPv6, INET6_ADDRSTRLEN);
		    inet_ntop(AF_INET6, &IPv6Header->ip6_dst, dstIPv6, INET6_ADDRSTRLEN);
            headerOffset += sizeof(struct ip6_hdr);
            /* Print ether type, src/dst IPs */
            printf(
                "ether type: IPv6\n"
                "src IP: %s\n"
                "dst IP: %s\n", srcIPv6, dstIPv6);

            /* Switch on IPv6's next header*/
            switch (IPv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
                /* TCP */
                case IPPROTO_TCP: {
                    struct tcphdr* tcpHeader = (struct tcphdr*) (packet + headerOffset);
                    /* Obtain source and destination ports */
                    srcPort = ntohs(tcpHeader->source);
                    dstPort = ntohs(tcpHeader->dest);
                    headerOffset += tcpHeader->doff*4;
                    printf("protocol: TCP\n");
                } break;

                /* UDP */
                case IPPROTO_UDP: {
                    struct udphdr* udpHeader = (struct udphdr*) (packet + headerOffset);
                    /* Obtain source and destination ports */
                    srcPort = ntohs(udpHeader->source);
                    dstPort = ntohs(udpHeader->dest);
                    headerOffset += sizeof(struct udphdr);
                    printf("protocol: UDP\n");
                } break;

                /* ICMPv6 */
                case IPPROTO_ICMPV6: {
                    struct icmp6_hdr* icmp6Header = (struct icmp6_hdr*) (packet + headerOffset);
                    headerOffset += sizeof(icmp6Header);
                    printf("Prototcol: ICMPv6\n");
                } break;
            }

            /* Print src/dst ports (if there are ports) */
            if (IPv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_ICMPV6)
                printf(
                    "src port: %d\n"
                    "dst port: %d\n", srcPort, dstPort);

        } break;


        /* ARP ether type */
        case ETHERTYPE_ARP: {
            struct ether_arp* ARPHeader = (struct ether_arp*) (packet + headerOffset);
            /* Get source and destination addresses, update header offset*/
            char srcARP[INET_ADDRSTRLEN];
            char dstARP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ARPHeader->arp_spa, srcARP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ARPHeader->arp_tpa, dstARP, INET_ADDRSTRLEN);
            headerOffset += sizeof(struct ether_arp);
            /* Print ether type, src/dst IPs */
            printf(
                "ether type: ARP\n"
                "src IP: %s\n"
                "dst IP: %s\n", srcARP, dstARP);
        } break;
    }
    *packetCounter = *packetCounter + 1; 


    /* Print entire packet */
    int i, j;
    for (i = 0; i < packetLength; i+=16) {
        printf("0x%.4x:  ", i);
        // write octets hexa-like 
        for (j = i; j < i + 16  and j < packetLength ; j++) {
            if (j == i + 8)
                printf(" ");
            printf("%02x ", (unsigned int)packet[j]);
        }
        /* Print "   " until it's time to print ascii */
        if (j < i + 9)
            printf(" ");
        while (j < i + 16) {
            j++;
            printf("   ");
        } 
        printf(" ");
        // write octets ascii-like 
        for (j = i; j < i + 16  and j < packetLength ; j++) {
            if (j == i + 8)
                printf(" ");
            if (isprint(packet[j]))
                printf("%c", packet[j]);
            else
                printf(".");
        }   
        printf("\n");
    }
}

void Sniffer::printInterfaces() {
    /* Find all devices */
    pcap_if_t* interfaces;
    if (pcap_findalldevs(&interfaces, errbuf) == PCAP_ERROR) {
        printf("No devices found\nError: %s\n", errbuf);
        return;
    }

    /* Printf the list of them */
    int counter = 0;
    printf("Interfaces available:\n");
    for (pcap_if_t* i = interfaces; i; i = i->next) {
        counter++;
        printf("%d. %s\n", counter, i->name);
    }
    pcap_freealldevs(interfaces);
}

void Sniffer::printHelp() {
    cout << "Usage: ./ipk-sniffer [-h|--help] [-i <interface>|--interface <interface>] [-p <port>] {[--tcp|-t] [--udp|-u] [--arp] [--icmp]} [-n <num>] \n"
                    "-h or --help - writes out help message \n"
                    "-i <interface> or --interface <interface> if there is no parameter writes out list of active interfaces, otherwise will add interface \n"
                    "-p <port> adds port filter \n"
                    "-t or --tcp will show only TCP packets \n"
                    "-u or --udp will show only UDP packets \n"
                    "-n <num> defines number of packets that will show up\n"
                    "--arp will show only only ARP frames \n"
                    "--icmp will show only ICMPv4 and ICMPv6 packets \n";
}