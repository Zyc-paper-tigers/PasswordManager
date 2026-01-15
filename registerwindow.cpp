#include "registerwindow.h"
#include "ui_registerwindow.h"
#include "loginwindow.h"
#include <QMessageBox>

RegisterWindow::RegisterWindow(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::RegisterWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("用户注册");
    if (!initDatabase()) {
        QMessageBox::critical(this, "错误", "数据库连接失败！");
        this->close();
    }
}

RegisterWindow::~RegisterWindow()
{
    delete ui;
    if (db.isOpen()) {
        db.close();
    }
}

bool RegisterWindow::initDatabase()
{
    db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("passwords.db");
    return db.open();
}

QString RegisterWindow::encrypt(const QString &plainText, const QString &key)
{
    QByteArray keyHash = QCryptographicHash::hash(key.toUtf8(), QCryptographicHash::Sha256);
    QByteArray plainBytes = plainText.toUtf8();
    for (int i = 0; i < plainBytes.size(); ++i) {
        plainBytes[i] ^= keyHash[i % keyHash.size()];
    }
    return plainBytes.toBase64();
}

// 注册按钮槽函数
void RegisterWindow::on_btnRegister_clicked()
{
    QString username = ui->leRegUsername->text().trimmed();
    QString password = ui->leRegPassword->text().trimmed();
    QString confirmPwd = ui->leRegConfirmPwd->text().trimmed();

    // 输入校验
    if (username.isEmpty() || password.isEmpty() || confirmPwd.isEmpty()) {
        ui->lblRegTip->setText("所有字段不能为空！");
        ui->lblRegTip->setStyleSheet("color: red;");
        return;
    }
    if (password != confirmPwd) {
        ui->lblRegTip->setText("两次密码输入不一致！");
        ui->lblRegTip->setStyleSheet("color: red;");
        ui->leRegPassword->clear();
        ui->leRegConfirmPwd->clear();
        return;
    }

    // 检查用户名是否已存在
    QSqlQuery checkQuery;
    checkQuery.prepare("SELECT id FROM user WHERE username = :username");
    checkQuery.bindValue(":username", username);
    if (checkQuery.exec() && checkQuery.next()) {
        ui->lblRegTip->setText("用户名已存在！");
        ui->lblRegTip->setStyleSheet("color: red;");
        return;
    }

    // 核心修改：直接存储明文密码，无需加密
    QString createTime = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    QSqlQuery insertQuery;
    insertQuery.prepare("INSERT INTO user (username, password, create_time) VALUES (:username, :password, :create_time)");
    insertQuery.bindValue(":username", username);
    insertQuery.bindValue(":password", password); // 明文存储
    insertQuery.bindValue(":create_time", createTime);

    if (insertQuery.exec()) {
        QMessageBox::information(this, "成功", "注册成功！请返回登录。");
        ui->leRegUsername->clear();
        ui->leRegPassword->clear();
        ui->leRegConfirmPwd->clear();
        ui->lblRegTip->clear();
    } else {
        ui->lblRegTip->setText("注册失败：" + insertQuery.lastError().text());
        ui->lblRegTip->setStyleSheet("color: red;");
    }
}

// 返回登录界面
void RegisterWindow::on_btnToLogin_clicked()
{
    LoginWindow *loginWin = new LoginWindow();
    loginWin->show();
    this->close();
}
