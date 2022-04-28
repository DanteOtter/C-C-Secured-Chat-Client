#include "ciphers.h"
#include "mainwindow.h"
#include "connector.h"
#include "encryptors.h"

#include <QApplication>


vector<QString> msgs = {"Not connected!\n"};
int option = 0;//Tells if host or guest
connector con(msgs);//passed to mainwindow

void chat_thread()
{//Thread to handle chat messages
    try
    {
        while(option == 0)
            continue;//wait until made choice

        if(option == 1)
        {//connect as guest
            con.guest();
        }
        else if(option == 2)
        {//connect at host
            con.host();
        }
    }
    catch (exception& e)
    {
        cout << e.what() << '\n';
    }
}

void file_thread()
{//thread for the files
    try
    {
        while(1)
        {//switch for if we are sending or receiving file.
            if(con.sending_file)
            {
                con.send_file();
            }
            else if(con.receiving_file)
            {
                con.receive_file();
                int a;
            }
        }
    }
    catch (exception& e)
    {
        cout << e.what() << '\n';
    }
}

void updater()
{
    try
    {
        auto time = std::chrono::system_clock::now().time_since_epoch();
        auto timer = std::chrono::milliseconds(300);

        while(1)
        {
            if(std::chrono::system_clock::now().time_since_epoch() - time >= timer)
            {
                msgs.push_back("apples\n");
                time = std::chrono::system_clock::now().time_since_epoch();
            }
        }
    }
    catch (exception& e)
    {
        cout << e.what() << '\n';
    }
}

void test_rotn(Ciphers& cip, std::string test)
{//test for ceaser cipher
    cip.rotn(test,13);
    cout << "rotn encoded: " << test << endl;
    cip.rotn_decipher(test,13);
    cout << "rotn decoded: " << test << endl;
}

void test_alpha(Ciphers& cip, std::string test)
{//test for alphabet substitution
    std::string alpha = cip.gen_alpha();
    cout << "Generated Alphabet: " << alpha << endl;
    cip.gen_alpha_maps(alpha);
    cip.alberti_encode(test);
    cout << "Encoded Alphabet: " << test << endl;
    cip.alberti_decode(test);
    cout << "Decoded Alphabet: " << test << endl;
}

void test_xor(Ciphers& cip, std::string test)
{//test for xor cipher
    std::string pass = "z";
    cip.xor_crypt(test, pass);
    cout << "XOR Encoded: " << test << endl;
    cip.vigenere_decipher(test, pass);
    cout << "XOR Decoded: " << test << endl;
}

void test_ciphers()
{//test the ciphers
    std::string test = "tuvwxyzYHello. My name is mike.";
    cout << "Original: " << test << endl;
    Ciphers cip;

    test_rotn(cip, test);
    test_alpha(cip, test);
    test_xor(cip, test);
}

void test_encryptors()
{//test encryption methods
    encryptors enc;
    enc.set_up();
    std::string data = "ttest";
    enc.aes_enc(data);
    cout << "Enc: " << data << endl;
    enc.aes_dec(data);
    cout << "Dec: " << data << endl;

    //enc.test();
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w(msgs, option, con);
    w.show();//initialize and show main window

    //test_ciphers();
    //test_encryptors();

    #ifdef __WIN32__
       WORD versionWanted = MAKEWORD(1, 1);
       WSADATA wsaData;//needed for windows tto find libraries
       WSAStartup(versionWanted, &wsaData);
    #endif
    //start our threads
    std::thread t1(chat_thread);
    std::thread t2(file_thread);
    //std::thread t2(updater);
    return a.exec();//run the application
}
