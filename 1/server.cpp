#include "server.hpp"

Server::Server(int port) { 
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "Socket creation failed" << endl;
        exit(1);
    }

    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT | SO_REUSEADDR, (const void*)&optval, sizeof(int));
    memset((char *)&address, 0, sizeof(address)); 
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY); 
    address.sin_port = htons((unsigned short)port);

    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        cerr << "Socket binding failed" << endl;
        exit(1);
    }

    setHostName();
    setCPUName();
}

Server::~Server() {
    close(fd);
}

void Server::setHostName() {
    gethostname(hostName, sizeof(hostName));
}

void Server::setCPUName() {
    int CPUInfo[4] = {-1};
    __cpuid(0x80000000, CPUInfo[0], CPUInfo[1], CPUInfo[2], CPUInfo[3]);
    int nExIds = CPUInfo[0];
    for (int i = 0x80000000; i <= nExIds; i++) {
        __cpuid(i, CPUInfo[0], CPUInfo[1], CPUInfo[2], CPUInfo[3]);
        if  (i == 0x80000002)
            memcpy(CPUName, CPUInfo, sizeof(CPUInfo));
        else if (i == 0x80000003)
            memcpy(CPUName + 16, CPUInfo, sizeof(CPUInfo));
        else if (i == 0x80000004)
            memcpy(CPUName + 32, CPUInfo, sizeof(CPUInfo));
    }
}

void Server::parseMessage() {
    std::string prefix = "HTTP/1.1 200 OK\r\nContent-Type:text/plain;\r\n\r\n";
    if (!strncmp(messageBuffer, "GET /hostname ", strlen("GET /hostname ")))
        response = hostName;
    else if (!strncmp(messageBuffer, "GET /cpu-name ", strlen("GET /cpu-name ")))
        response = CPUName;
    else if (!strncmp(messageBuffer, "GET /load ", strlen("GET /load ")))
        getCPULoad();
    else {
        response = "HTTP/1.1 400 BAD REQUEST\r\nContent-Type: text/plain;\r\n\r\n400 Bad Request!\n";
        return;
    }
    response = prefix + response + "\n";
}

void Server::getCPULoad() {
    int totalJiffies1, totalJiffies2, busyJiffies1, busyJiffies2;
    int cpuLoad;
    calculateCurrentCPULoad(totalJiffies1, busyJiffies1);
    sleep(5);
    calculateCurrentCPULoad(totalJiffies2, busyJiffies2);
    cpuLoad = (busyJiffies2 - busyJiffies1) * 100 / (totalJiffies2 - totalJiffies1);
    response = to_string(cpuLoad) + "%";
}

void Server::calculateCurrentCPULoad(int &total, int &busy) {
    ifstream infile("/proc/stat");
    if (infile.good()) {
        string sLine;
        vector<string> tmpVs;
        vector<int> tmpVi;
        getline(infile, sLine);

        istringstream iss(sLine);
        for (string token; getline(iss, token, ' '); ) 
            tmpVs.push_back(token);

        transform(tmpVs.begin() + 2, tmpVs.end(), back_inserter(tmpVi),
                [](const string &s) { return stoi(s); });

        total = tmpVi[0] + tmpVi[1] + tmpVi[2] + tmpVi[3] + tmpVi[4] + tmpVi[6];
        busy = tmpVi[0] + tmpVi[1] + tmpVi[2];
    }
}

void Server::waitForConnection() {
    int addrLen, newSocket;

    if (listen(fd, MAX_NUMBER_OF_CONNECTIONS) < 0) {
        cerr << "Listening failed" << endl;
        exit(1);
    }

    addrLen = sizeof(address);
    while (1) {
        if ((newSocket = accept(fd, (struct sockaddr *)&address, (socklen_t*)&addrLen)) < 0) {
            cerr << "Acception failed" << endl;
            exit(1);
        }
        read(newSocket, messageBuffer, BUFFER_SIZE);
        parseMessage();
        write(newSocket, response.data(), response.length());
        close(newSocket);
    }
}
