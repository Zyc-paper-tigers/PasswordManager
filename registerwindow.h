#ifndef REGISTERWINDOW_H
#define REGISTERWINDOW_H

#include <QWidget>
#include <QSqlDatabase>
#include <QDateTime>
#include <QCryptographicHash>

namespace Ui {
class RegisterWindow;
}

class RegisterWindow : public QWidget
{
    Q_OBJECT

public:
    explicit RegisterWindow(QWidget *parent = nullptr);
    ~RegisterWindow();

private slots:
    void on_btnRegister_clicked();    // 注册按钮
    void on_btnToLogin_clicked();     // 返回登录界面

private:
    Ui::RegisterWindow *ui;
    QSqlDatabase db;
    bool initDatabase();
    QString encrypt(const QString &plainText, const QString &key = "MySecretKey123");
};

#endif // REGISTERWINDOW_H
