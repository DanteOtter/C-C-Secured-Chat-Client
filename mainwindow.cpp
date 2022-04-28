#include "mainwindow.h"
#include <QtWidgets>
#include "./ui_mainwindow.h"
#include <sstream>

MainWindow::MainWindow(vector<QString>& handle, int& options, connector& conn, QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , msgs(handle)
    , option(options)
    , con(conn)
{
    ui->setupUi(this);
    set_defaults();

    QTimer *timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &MainWindow::update_window);
    timer->start(300);

    ui->pushButton->hide();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::set_defaults()
{
    ui->avail_files->setText("No files to show...");
    ui->file_folder->insertPlainText("");
    ui->ip->insertPlainText("127.0.0.1");
    ui->password->insertPlainText("");
    ui->port->setValue(3000);
}

void MainWindow::update_window()
{
    if(msgs.size() > length)
    {
        length = msgs.size();
        std::string chat;
        int max_scroll = ui->chat_window->verticalScrollBar()->maximum();
        for (vector<QString>::iterator t=msgs.begin(); t!=msgs.end(); ++t)
        {
            chat += t->toStdString();
        }
        ui->chat_window->setText(QString::fromStdString(chat));
        ui->chat_window->verticalScrollBar()->setValue(max_scroll);
    }


}

void MainWindow::on_sender_clicked()
{
    //get all relevant information
    int port = get_port(),
        rotn = ui->rotn->value();
    std::string ip = get_ip();
    std::string xor_key = get_password(),
                alpha = ui->Alpha->toPlainText().toStdString(),
                folder = ui->file_folder->toPlainText().toStdString();
    bool XOR = ui->XOR->isChecked(),
         ceaser = ui->ceaser->isChecked(),
         subs = ui->subs->isChecked(),
         rev = ui->reverse->isChecked(),
         aes = ui->aes->isChecked(),
         ssl = ui->ssl->isChecked();


    if(folder.length())
    {//only return a folder and contents if something was specified
        std::string files = "";
        file_list = get_files(ui->file_folder->toPlainText().toStdString());
        for (vector<QString>::iterator t=file_list.begin(); t!=file_list.end(); ++t)
        {
            files += t->toStdString() + "\n";
        }
        ui->avail_files->setText(QString::fromStdString(files));
    }

    if(!ssl)
    {//case for ssl connections
        con.client_setup(port, ip, xor_key, XOR, ceaser, subs, rev, aes, rotn, alpha, folder, file_list);
    }
    else
    {
        //ssl_con.client_setup(port, ip, xor_key, XOR, ceaser, subs, aes, rotn);
    }


    option = 1;
}

void MainWindow::on_receiver_clicked()
{
    //get all relevant information
    int port = get_port(),
        rotn = ui->rotn->value();
    std::string ip = get_ip();
    std::string xor_key = get_password(),
                alpha = ui->Alpha->toPlainText().toStdString(),
            folder = ui->file_folder->toPlainText().toStdString();
    bool XOR = ui->XOR->isChecked(),
         ceaser = ui->ceaser->isChecked(),
         subs = ui->subs->isChecked(),
         rev = ui->reverse->isChecked(),
         aes = ui->aes->isChecked(),
         ssl = ui->ssl->isChecked();


    if(folder.length())
    {//only return a folder and contents if something was specified
        std::string files = "";
        file_list = get_files(ui->file_folder->toPlainText().toStdString());
        for (vector<QString>::iterator t=file_list.begin(); t!=file_list.end(); ++t)
        {
            files += t->toStdString() + "\n";
        }
        ui->avail_files->setText(QString::fromStdString(files));
    }

    if(!ssl)
    {//case for ssl connections
            con.host_setup(port, ip, xor_key, XOR, ceaser, subs, rev, aes, rotn, alpha, folder, file_list);
    }
    else
    {
        //ssl_con.host_setup(port, password, XOR, ceaser, subs, aes, rotn);
    }

    option = 2;
}

std::string MainWindow::get_ip()
{//get supplied ip
    return ui->ip->toPlainText().toStdString();
}
std::string MainWindow::get_password()
{//get supplied port
    return ui->password->toPlainText().toStdString();
}
std::string MainWindow::get_file_folder()
{//get folder
    return ui->file_folder->toPlainText().toStdString();
}
int MainWindow::get_port()
{//get port number
    return ui->port->value();
}

vector<QString> MainWindow::get_files(std::string path)
{//get list of files
    vector<QString> files;
    //loop all files in selected directory
    for (const auto & file : std::filesystem::directory_iterator(path))
            files.push_back(QString::fromStdString(file.path().filename().string()));

    return files;
}

void MainWindow::on_Poster_clicked()
{//send message
    std::string msg = ui->chat_box->toPlainText().toStdString();
    con.send_msg(msg);
}


void MainWindow::on_pushButton_clicked()
{//Force file closer for testing on the receiving end
    con.file_out.close();
}

