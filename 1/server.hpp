#ifndef server_hpp
#define server_hpp

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string>
#include <array>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <cstdlib>
#include <sys/utsname.h>
#include <cpuid.h>
#include <sstream>
#include <iomanip>
#include <regex>
#include <fstream>
#include <valarray>

#define BUFFER_SIZE 1024
#define MAX_NUMBER_OF_CONNECTIONS 118 // Ecc. 1:18

using namespace std;

class Server {

    private:

        int fd;                                             // server's file descriptor
        struct sockaddr_in address;                         // socket's address

        char messageBuffer[BUFFER_SIZE];                    // user's message
        char hostName[255];                                 // name of the host
        char CPUName[64];                                   // name of the CPU
        string response;                                    // server's answer
        
        /**
         * @brief Sets the name of the host
         * 
         */
        void setHostName();

        /**
         * @brief Sets the name of the CPU
         * 
         */
        void setCPUName();

        /**
         * @brief Calculates CPU load
         * 
         * @return string 
         */
        void getCPULoad();

        /**
         * @brief Reads /proc/stat file and gets information about number of jiffies
         * 
         */
        void calculateCurrentCPULoad(int &total, int &busy);

        /**
         * @brief Parses input message and returns a server's response
         * 
         */
        void parseMessage();

    public:

        /**
         * @brief Constructs a new Server object based on port number, creates socket, sets attributes
         * 
         * @param port port number
         */
        Server(int port);

        /**
         * @brief Destroys the Server object
         * 
         */
        ~Server();

        /**
         * @brief Waits and listens to requests
         * 
         */
        void waitForConnection();
        
};

#endif 