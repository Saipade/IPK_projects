#include "server.hpp"

using namespace std;

int main(int argc, char* argv[]) {
    
    string port = argv[1];

    if (argc != 2) {
        cerr << "Incorrect number of arguments." << endl << "Use: " << argv[0] << " <server address>" << endl << "See Readme.md for more help." << endl;      
        exit(1);
    }
    
    if (port.find_first_not_of("0123456789") != string::npos) {
        cerr << "Incorrect format of port." << endl << "The only valid format is numeric." << endl << "See Readme.md for more help." << endl;
        exit(1);
    }

    Server *server = new Server(stoi(port));
    server->waitForConnection();
    return 0;

}