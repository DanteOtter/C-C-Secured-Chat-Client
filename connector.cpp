#include "connector.h"

connector::connector(vector<QString>& m):
    msgs(m)
{
    enc.set_up();
}

bool connector::host_setup(int port, std::string ip, std::string xor_key, bool XOR, bool ceaser, bool subs, bool rev, bool aes, int rotn, std::string alpha, std::string folder, vector<QString> file_list)
{
    cipher.set_up(xor_key,XOR,ceaser,subs,rev,rotn,alpha);
    this->ip = ip;
    this->port = port;
    this->password = xor_key; //Setup the initial parameters
    this->aes = aes;
    this->folder = folder;
    this->file_list = file_list;

    //Create the socket and feed info
    bzero((char*)&SockAddr, sizeof(SockAddr));
    SockAddr.sin_family = AF_INET;
    SockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    SockAddr.sin_port = htons(port);

    //Initialize the socket descriptor
    socketSD = socket(AF_INET, SOCK_STREAM, 0);
    if(socketSD < 0)
    {
        cerr << "Could not open socket!!!" << endl;
        exit(0);
    }
    //bind the socket to its local address
    int bindStatus = bind(socketSD, (struct sockaddr*) &SockAddr,
        sizeof(SockAddr));
    if(bindStatus < 0)
    {
        cerr << "Could not bind socket ip" << endl;
        exit(0);
    }
    cout << "Waiting for guest" << endl;
    //listen for up to 1 requests at a time
    listen(socketSD, 1);
    is_host = true;
    initialized = true;
    return 0;
}

bool connector::client_setup(int port, std::string ip, std::string xor_key, bool XOR, bool ceaser, bool subs, bool rev, bool aes, int rotn, std::string alpha, std::string folder, vector<QString> file_list)
{
    cipher.set_up(xor_key,XOR,ceaser,subs,rev,rotn,alpha);
    this->port = port;
    this->ip = ip;
    this->password = xor_key;   //Setup the initial parameters
    this->aes = aes;
    this->folder = folder;
    this->file_list = file_list;
    cout<<"Connecting to socket!"<<endl;
    msgs.push_back("Connecting to socket!\n");

    //Create the socket and feed info
    host_struct = gethostbyname(ip.c_str());
    bzero((char*)&SockAddr, sizeof(SockAddr));
    SockAddr.sin_family = AF_INET;
    SockAddr.sin_addr.s_addr = inet_addr(
                inet_ntoa(*(struct in_addr*)*host_struct->h_addr_list));
    SockAddr.sin_port = htons(port);
    socketSD = socket(AF_INET, SOCK_STREAM, 0);

    //Initial connection attempt
    int status = connect(socketSD,
                 (sockaddr*) &SockAddr, sizeof(SockAddr));
    if(status < 0)
    { //Connection failed
        std::chrono::milliseconds retry = std::chrono::duration_cast< std::chrono::milliseconds >(std::chrono::system_clock::now().time_since_epoch());
        std::chrono::milliseconds now = std::chrono::duration_cast< std::chrono::milliseconds >(std::chrono::system_clock::now().time_since_epoch());

        while(status < 0)
        {//Retry connection till succeed
            if(now.count() - retry.count() >= 1000)
            {//Once per second
                cout<<"Error connecting. Retrying..."<<endl;
                msgs.push_back("Error connecting. Retrying...\n");
                close(socketSD);
                socketSD = socket(AF_INET, SOCK_STREAM, 0);
                status = connect(socketSD,
                         (sockaddr*) &SockAddr, sizeof(SockAddr));
                retry = now;
            }
            now = std::chrono::duration_cast< std::chrono::milliseconds >(std::chrono::system_clock::now().time_since_epoch());
        }
    }

    cout << "Connected to host!" << endl;
    msgs.push_back("Connected to host!\n");
    initialized = true;
    return 0;
}

bool connector::send_msg(std::string data)
{
    if(initialized)
    {//Don't send until everything initialized
        if(data.length() > 464)
        {//Max message length of 464 characters.
            msgs.push_back(QString::fromStdString("The character limit is 464, but your input is " + std::to_string(data.length()) + " character long."));
            return false;
        }
        else
        {
            if(!data.find("/Request"))
            {//We requested file
                requesting_file = true;
            }

            std::string temp = data;
            memset(&msg, 0, sizeof(msg));//clear the buffer
            cipher.cipher(data);//Cipher the message
            if(aes) enc.aes_enc(data);//encrypt the data
            strncpy(msg, data.c_str(), sizeof(msg));
            auto b64 = enc.base64_encode((unsigned char*)msg, std::strlen(msg));//encode the data
            send(is_host ? newSd : socketSD, b64, std::strlen(b64), 0);//send the data
            msgs.push_back(QString::fromStdString("Me: " + temp + "\n"));//log original message
            return false;
        }

    }
    return false;
}

void connector::send_file()
{
    sending_file = false;
    //create sockets and feed initial info
    sockaddr_in file_sock;
    sockaddr_in new_file_sock;
    socklen_t new_file_sock_size = sizeof(new_file_sock);
    bzero((char*)&file_sock, sizeof(file_sock));
    file_sock.sin_family = AF_INET;
    file_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    file_sock.sin_port = htons(port + 1);


    int file_sd = socket(AF_INET, SOCK_STREAM, 0);
    if(file_sd < 0)
    {//Attempt to open socket
        cerr << "Could not open socket!!!" << endl;
        exit(0);
    }
    //bind the socket to its local address
    int bindStatus = bind(file_sd, (struct sockaddr*) &file_sock,
        sizeof(file_sock));
    if(bindStatus < 0)
    {
        cerr << "Could not bind socket ip" << endl;
        exit(0);
    }
    cout << "Waiting for guest" << endl;
    //listen for up to 1 requests at a time
    listen(file_sd, 1);


    //accept connection
    int new_file_sd = accept(file_sd, (sockaddr *)&new_file_sock, &new_file_sock_size);
    if(new_file_sd < 0)
    {
        cerr << "Could not accept request" << endl;
        exit(0);
    }
    cout << "Connected with guest!" << endl;
    msgs.push_back("Connected with guest!\n");


    int bytes_sent = 0;
    char file[256];
    int file_size = file_in.tellg();
    file_in.seekg(0, ios::beg);
    cout << file_size << endl;
    //Get the filesize and send to recipient
    memset(&file, 0, sizeof(file));//clear the buffer
    strncpy(file, std::to_string(file_size).c_str(), sizeof(file));//clear the buffer
    //enc.base64_encode((unsigned char*)file, std::strlen(file));
    send(new_file_sd, (char*)&file, strlen(file), 0);
    do
    {     //read file to buffer
        memset(&file, 0, sizeof(file));//clear the buffer
        file_in.read(file, sizeof(file));
        std::string f(file);
        //cipher.cipher(f);
        //if(aes) enc.aes_enc(f);
        strncpy(file, f.c_str(), sizeof(f));
        //enc.base64_encode((unsigned char*)file, std::strlen(file));
        bytes_sent += send(new_file_sd, (char*)&file, strlen(file), 0);
        std::cout << bytes_sent << std::endl;
    }while(!file_in.eof());
    cout << "Done Sending......" << endl;
    msgs.push_back("Done Sending......");

    file_in.close();//close file and connection
    close(file_sd);
    close(new_file_sd);
}

void connector::receive_file()
{
    receiving_file = false;
    sockaddr_in file_sock;
    struct hostent* file_host_struct;
    //setup a socket and feed information
    file_host_struct = gethostbyname(ip.c_str());
    bzero((char*)&file_sock, sizeof(file_sock));
    file_sock.sin_family = AF_INET;
    file_sock.sin_addr.s_addr = inet_addr(
                inet_ntoa(*(struct in_addr*)*file_host_struct->h_addr_list));
    file_sock.sin_port = htons(port + 1);
    int file_sd = socket(AF_INET, SOCK_STREAM, 0);

    //attempt to connect
    int status = connect(file_sd,
                 (sockaddr*) &file_sock, sizeof(file_sock));
    if(status < 0)
    {//connection failed
        std::chrono::milliseconds retry = std::chrono::duration_cast< std::chrono::milliseconds >(std::chrono::system_clock::now().time_since_epoch());
        std::chrono::milliseconds now = std::chrono::duration_cast< std::chrono::milliseconds >(std::chrono::system_clock::now().time_since_epoch());

        while(status < 0)
        {//retry connection every second until success
            if(now.count() - retry.count() >= 1000)
            {
                cout<<"Error connecting! Retrying..."<<endl;
                //msgs.push_back("Error connecting to socket! Retrying connection...\n");
                close(file_sd);
                file_sd = socket(AF_INET, SOCK_STREAM, 0);
                status = connect(file_sd,
                         (sockaddr*) &file_sock, sizeof(file_sock));
                retry = now;
            }
            now = std::chrono::duration_cast< std::chrono::milliseconds >(std::chrono::system_clock::now().time_since_epoch());
        }
    }

    cout << "Connected to host!" << endl;
    //msgs.push_back("Connected to the server!\n");

    int bytes_read = 0;
    char file[256];
    recv(file_sd, (char*)&file, sizeof(file), 0);
    //enc.base64_decode(file, std::strlen(file));
    int size = atoi(file);//Get the file size
    memset(&file, 0, sizeof(file));//clear the buffer
    cout << size << endl;
    while(bytes_read < size)
    {//Keep going until we get all bytes
        bytes_read += recv(file_sd, (char*)&file, sizeof(file), 0);
        //enc.base64_decode(file, sizeof(file));

        std::string converted_msg(file);
        //if(aes) enc.aes_dec(converted_msg);
        //cipher.decipher(converted_msg);
        cout << bytes_read << endl;
        file_out << converted_msg;
        memset(&file, 0, sizeof(file));//clear the buffer
    }
    file_out.close();//Close file and connection
    msgs.push_back("File Downloaded...");
    close(file_sd);
}

std::string connector::filename_from_request(std::string data)
{
    std::string filename = data.substr(data.find(" "));
    trim(filename);
    return filename;
}

void connector::guest()
{
    while(1)
    {//Main run loop
        recv(socketSD, (char*)&msg, sizeof(msg), 0);
        if(strlen(msg))
        {//We can't process empty strings
            std::string converted_msg1(msg);
            cout << "Original: " << converted_msg1 << endl;
            auto b64 = enc.base64_decode((char*)msg, std::strlen(msg));
            std::string converted_msg(b64);//Decode
            if(aes) enc.aes_dec(converted_msg);//Decryptt
            cipher.decipher(converted_msg);//Decipher
            msgs.push_back(QString::fromStdString("Them: " + converted_msg + "\n"));
            memset(&msg, 0, sizeof(msg));//clear the buffer

            if(!strcmp(msg, "/exit"))
            {//close our connection
                cout << "Server has quit the session" << endl;
                send_msg("/exit");//tell them to close as well
                break;
            }


            if(!converted_msg.find("/Sending") && requesting_file)
            {//confirm file send, but only if we requested
                cout << "Getting File" << endl;
                file_name = filename_from_request(converted_msg);//get filename
                if((converted_msg.find("..") == std::string::npos) || (converted_msg.find("/") == std::string::npos) || (converted_msg.find("\\") == std::string::npos))
                {//check for directory pathing
                    file_out.open(folder + file_name, ios::out|ios::binary);
                    if(file_out.good())
                    {//check that we can open file
                        receiving_file = true;
                        requesting_file = false;
                    }
                    else
                    {
                        file_out.close();
                    }
                }
                else
                {
                    msgs.push_back(QString::fromStdString("User attempted to enter another directory"));
                }
            }

            if(!converted_msg.find("/Request"))
            {//get request
                if((converted_msg.find("..") == std::string::npos) || (converted_msg.find("/") == std::string::npos) || (converted_msg.find("\\") == std::string::npos))
                {//check for paths
                    cout << "Partner has requested file" << endl;
                    file_name = filename_from_request(converted_msg);

                    if(std::find(file_list.begin(), file_list.end(), QString::fromStdString(file_name)) != file_list.end())
                    {//file exists
                        msgs.push_back(QString::fromStdString("Partner has requested: " + file_name + "\n"));
                        file_in.open(folder + file_name, ios::in|ios::binary|ios::ate);
                        if(file_in.good())
                        {//check that we can open it
                            send_msg("/Sending " + file_name);
                            sending_file = true;//confirm send
                        }
                        else
                        {
                            file_in.close();
                        }
                    }
                }
            }
            requesting_file = false;
        }
    }
    close(socketSD);
}


void connector::host()
{
    try
    {

        //accept, create a new socket descriptor to
        //handle the new connection with client
        newSd = accept(socketSD, (sockaddr *)&newSockAddr, &newSockAddrSize);
        if(newSd < 0)
        {
            cerr << "Error accepting request from client!" << endl;
            exit(1);
        }
        msgs.push_back("Connected with guest!\n");
        cout << "Connected with guest!" << endl;
        while(1)
        {
            recv(newSd, (char*)&msg, sizeof(msg), 0);
            if(true | strlen(msg))
            {
                std::string converted_msg1(msg);
                cout << "Original: " << converted_msg1 << endl;
                auto b64 = enc.base64_decode((char*)msg, std::strlen(msg));//Decode
                std::string converted_msg(b64);
                cout << "b64 Decode: " << converted_msg << endl;
                if(aes) enc.aes_dec(converted_msg);//Decrypt
                cipher.decipher(converted_msg);//Decipher
                msgs.push_back(QString::fromStdString("Them: " + converted_msg + "\n"));
                memset(&msg, 0, sizeof(msg));//clear the buffer

                if(!strcmp(msg, "/exit"))
                {//close our connection
                    cout << "Server has quit the session" << endl;
                    send_msg("/exit");//tell them to close as well
                    break;
                }


                if(!converted_msg.find("/Sending") && requesting_file)
                {//confirm file send, but only if we requested
                    cout << "Getting File" << endl;
                    file_name = filename_from_request(converted_msg);//get filename
                    if((converted_msg.find("..") == std::string::npos) || (converted_msg.find("/") == std::string::npos) || (converted_msg.find("\\") == std::string::npos))
                    {//check for directory pathing
                        file_out.open(folder + file_name, ios::out|ios::binary);
                        if(file_out.good())
                        {//check that we can open file
                            receiving_file = true;
                            requesting_file = false;
                        }
                        else
                        {
                            file_out.close();
                        }
                    }
                    else
                    {
                        msgs.push_back(QString::fromStdString("User attempted to enter another directory"));
                    }
                }

                if(!converted_msg.find("/Request"))
                {//get request
                    if((converted_msg.find("..") == std::string::npos) || (converted_msg.find("/") == std::string::npos) || (converted_msg.find("\\") == std::string::npos))
                    {//check for paths
                        cout << "Partner has requested file" << endl;
                        file_name = filename_from_request(converted_msg);

                        if(std::find(file_list.begin(), file_list.end(), QString::fromStdString(file_name)) != file_list.end())
                        {//file exists
                            msgs.push_back(QString::fromStdString("Partner has requested: " + file_name + "\n"));
                            file_in.open(folder + file_name, ios::in|ios::binary|ios::ate);
                            if(file_in.good())
                            {//check that we can open it
                                send_msg("/Sending " + file_name);
                                sending_file = true;//confirm send
                            }
                            else
                            {
                                file_in.close();
                            }
                        }
                    }
                }
                requesting_file = false;
            }
        }
        //close our sockets
        close(newSd);
        close(socketSD);
    }
    catch (exception& e)
    {
        cout << e.what() << '\n';
    }
}
