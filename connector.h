#ifndef CONNECTOR_H
#define CONNECTOR_H
#include <iostream>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <fcntl.h>
#include <fstream>
#include <vector>
#include <thread>
#include <time.h>
#include <QMainWindow>
#include "ciphers.h"
#include "encryptors.h"
//#include "./ui_mainwindow.h"

#ifdef __WIN32__
# include <winsock2.h>
#include <ws2tcpip.h>
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#define bcopy(b1,b2,len) (memmove((b2), (b1), (len)), (void) 0)
#else
# include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/wait.h>
#endif


using namespace std;


class connector
{
    public:
        //connector();
        connector(vector<QString>&);
        connector(int, char*);

        void host();
        void guest();
        void send_file();
        void receive_file();
        bool send_msg(std::string);
        std::string filename_from_request(std::string);
        bool sending_file = false,
             receiving_file = false;
        bool host_setup(int, std::string, std::string, bool, bool, bool, bool, bool, int, std::string, std::string, vector<QString>);
        bool client_setup(int, std::string, std::string, bool, bool, bool, bool, bool, int, std::string, std::string, vector<QString>);
        std::ifstream file_in;
        std::ofstream file_out;

    private:
        int port = 3000,
            socketSD,
            newSd;
        bool is_host = false,
             initialized = false,
             aes = false,
             requesting_file = false;
        char msg[4096];
        std::string ip = "127.0.0.1",
                    password = "",
                    file_name = "",
                    folder = "";
        sockaddr_in SockAddr;

        vector<QString>& msgs;
        vector<QString> file_list;
        struct hostent* host_struct;

        sockaddr_in newSockAddr;
        socklen_t newSockAddrSize = sizeof(newSockAddr);

        Ciphers cipher;
        encryptors enc;

        // trim from start (in place)
        static inline void ltrim(std::string &s) {
            s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
                return !std::isspace(ch);
            }));
        }

        // trim from end (in place)
        static inline void rtrim(std::string &s) {
            s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
                return !std::isspace(ch);
            }).base(), s.end());
        }

        // trim from both ends (in place)
        static inline void trim(std::string &s) {
            ltrim(s);
            rtrim(s);
        }
};

#endif // CONNECTOR_H
