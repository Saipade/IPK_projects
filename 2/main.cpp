/**
 * @author Maksim Tikhonov (xtikho00)
 * @brief Main file
 * 
 */

#include "sniffer.hpp"

/**
 * @brief Main function
 *   
 **/
int main(int argc, char* argv[]) {
    Sniffer* sniffer = new Sniffer();
    sniffer->parseArguments(argc, argv);
    sniffer->openDevice();
    sniffer->sniff();

    return 0;
}