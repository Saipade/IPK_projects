/**
 * @file sniffer.hpp
 * @author Maksim Tikhonov (xtikho00)
 * @brief Interface of the Sniffer class
 * 
 */

#ifndef SNIFFER_HPP
#define SNIFFER_HPP

#include <string>
#include <pcap.h>
#include <getopt.h>

#define MAC_LEN 19 // format: dd:dd:dd:dd:dd:dd

/**
 * @brief Sniffer class
 * 
 */
class Sniffer {

private: 

    pcap_t *handle;                         // pcap descriptor
    char errbuf[PCAP_ERRBUF_SIZE];          // error buffer for pcap library functions

    std::string filter;                     // filter expression
    std::string interface;                  // device to sniff on  
    std::string port;                       // port string
    bool tcp = true;
    bool udp = true;
    bool icmp = true;
    bool arp = true;
    int packetNumber = 1;                   // number of packets to be sniffed
    u_char packetCounter;                   // counter of packets

    /**
     * @brief Prints out the help message
     * 
     */
    void printHelp();

    /**
     * @brief Prints out the list of interfaces
     * 
     */
    void printInterfaces();

public:

    /**
     * @brief Parses the command line arguments
     * 
     */
    void parseArguments(int argc, char* argv[]);

    /**
     * @brief Initialises the pcap library, opens given device and installs a filter
     * 
     */
    void openDevice();

    /**
     * @brief Starts sniffing via pcap_loop for <packetNumber> packets
     * 
     */
    void sniff();
    
};

/* getopt command line options */
const char* const shortOptions = "hi::p:tun:";
const struct option longOptions[] = {
    {"help", no_argument, 0, 'h'},
    {"interface", optional_argument, 0, 'i'},
    {"tcp", no_argument, 0, 't'},
    {"udp", no_argument, 0, 'u'},
    {"arp", no_argument, 0, 'a'},
    {"icmp", no_argument, 0, 'c'},
    {NULL, 0, 0, '\0'}
};

#endif