#include "loginwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{

    QApplication a(argc, argv);
    LoginWindow loginWin; // 启动登录窗口
    loginWin.show();
    return a.exec();
}
