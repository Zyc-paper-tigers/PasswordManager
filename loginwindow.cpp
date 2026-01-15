#include "loginwindow.h"
#include "ui_loginwindow.h"
#include <QCryptographicHash>

LoginWindow::LoginWindow(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::LoginWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("用户登录");
    // 初始化数据库
    if (!initDatabase()) {
        QMessageBox::critical(this, "错误", "数据库连接失败！");
        this->close();
    }
}

LoginWindow::~LoginWindow()
{
    delete ui;
    if (db.isOpen()) {
        db.close();
    }
}

// 初始化数据库（和主窗口一致）
bool LoginWindow::initDatabase()
{
    db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("passwords.db");
    return db.open();
}

// 加密函数（和密码库加密逻辑一致）
/*QString LoginWindow::encrypt(const QString &plainText, const QString &key)
{
    QByteArray keyHash = QCryptographicHash::hash(key.toUtf8(), QCryptographicHash::Sha256);
    QByteArray plainBytes = plainText.toUtf8();
    for (int i = 0; i < plainBytes.size(); ++i) {
        plainBytes[i] ^= keyHash[i % keyHash.size()];
    }
    return plainBytes.toBase64();
}*/

// 登录按钮槽函数
void LoginWindow::on_btnLogin_clicked()
{
    QString username = ui->leLoginUsername->text().trimmed();
    QString password = ui->leLoginPassword->text().trimmed();

    // 输入校验
    if (username.isEmpty() || password.isEmpty()) {
        ui->lblTip->setText("用户名或密码不能为空！");
        ui->lblTip->setStyleSheet("color: red;");
        return;
    }

    // 核心修改：直接比对明文密码，无需加密
    QSqlQuery query;
    query.prepare("SELECT id FROM user WHERE username = :username AND password = :password");
    query.bindValue(":username", username);
    query.bindValue(":password", password); // 直接用明文比对

    if (query.exec() && query.next()) {
        // 登录成功：获取用户ID，打开主窗口，关闭登录窗口
        int userId = query.value(0).toInt();
        MainWindow *mainWin = new MainWindow(userId); // 传递当前登录用户ID
        mainWin->show();
        this->close();
    } else {
        ui->lblTip->setText("用户名或密码错误！");
        ui->lblTip->setStyleSheet("color: red;");
        ui->leLoginPassword->clear();
    }
}

// 跳转到注册界面
void LoginWindow::on_btnToRegister_clicked()
{
    RegisterWindow *regWin = new RegisterWindow();
    regWin->show();
    this->hide(); // 隐藏登录窗口，注册完成后可返回
}
