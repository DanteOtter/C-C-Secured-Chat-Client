#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "./ui_mainwindow.h"
#include "connector.h"
#include <filesystem>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(vector<QString>&,int&, connector&, QWidget *parent = nullptr);
    void create_msg_handler(vector<QString>&);
    void update();
    std::string get_ip();
    std::string get_password();
    std::string get_file_folder();
    int get_port();
    ~MainWindow();

public slots:
    void update_window();

private slots:
    void on_receiver_clicked();
    void on_sender_clicked();

    void on_Poster_clicked();

    void on_pushButton_clicked();

private:
    Ui::MainWindow *ui;
    vector<QString>& msgs;
    int& option;
    connector& con;
    void set_defaults();
    int length = 0;
    vector<QString> get_files(std::string);
    vector<QString> file_list;

};
#endif // MAINWINDOW_H
