#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QMessageBox>
#include <QDateTime>
#include <QFileDialog>
#include <QFile>
#include <QCryptographicHash>
#include <QTextStream>
#include <QTableWidgetItem>

// 自动生成的UI类命名空间
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    // 构造函数：接收当前登录用户ID，实现用户数据隔离
    explicit MainWindow(int currentUserId, QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    // 核心功能槽函数
    void on_btnAdd_clicked();         // 添加账号
    void on_btnUpdate_clicked();      // 修改账号
    void on_btnDelete_clicked();      // 删除账号
    void on_btnFilter_clicked();      // 分类筛选
    void on_btnBackup_clicked();      // 备份数据
    void on_btnImport_clicked();      // 导入加密文件
    void on_btnExport_clicked();      // 导出加密文件

    // 扩展功能槽函数
    void on_tableWidget_itemSelectionChanged(); // 表格选中行变化（填充/清空输入框）
    void on_btnShowPassword_clicked();          // 显示解密后的原密码
    void on_btnClearInputs_clicked();           // 一键清空输入框

private:
    Ui::MainWindow *ui;               // 指向UI界面的指针
    QSqlDatabase db;                  // SQLite数据库对象
    const QString ENCRYPT_KEY = "PasswordManager2026_Key"; // 加密密钥（可自定义）
    int m_currentUserId;              // 当前登录用户ID（核心：实现用户数据隔离）

    // 核心工具函数
    bool initDatabase();              // 初始化数据库（创建/连接表）
    QString encrypt(const QString &plainText); // 加密函数（哈希+异或+Base64）
    QString decrypt(const QString &cipherText); // 解密函数
    void loadDataToTable(const QString &category = "全部"); // 加载当前用户的密码数据到表格
    void loadCategoriesToCombo();     // 加载当前用户的分类到下拉框
    void clearInputs();               // 清空所有输入框
};

#endif // MAINWINDOW_H
