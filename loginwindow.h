#ifndef LOGINWINDOW_H
#define LOGINWINDOW_H

#include <QWidget>
#include <QSqlDatabase>
#include <QMessageBox>
#include "mainwindow.h"
#include "registerwindow.h"

namespace Ui {
class LoginWindow;
}

class LoginWindow : public QWidget
{
    Q_OBJECT

public:
    explicit LoginWindow(QWidget *parent = nullptr);
    ~LoginWindow();

private slots:
    void on_btnLogin_clicked();       // 登录按钮
    void on_btnToRegister_clicked();  // 跳转到注册界面

private:
    Ui::LoginWindow *ui;
    QSqlDatabase db;
    // 初始化数据库连接（复用主窗口逻辑）
    bool initDatabase();
    // 加密用户登录密码（和密码库加密逻辑一致）
    QString encrypt(const QString &plainText, const QString &key = "MySecretKey123");
};

#endif // LOGINWINDOW_H
