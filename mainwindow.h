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

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
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
    void on_tableWidget_itemSelectionChanged(); // 表格选中行变化
    void on_btnShowPassword_clicked();          // 显示原密码（无需解密）
    void on_btnClearInputs_clicked();           // 一键清空输入框

private:
    Ui::MainWindow *ui;               // 指向UI界面的指针
    QSqlDatabase db;                  // SQLite数据库对象
    // 注：加密密钥仅保留（若需用户登录密码加密），密码库密码不再加密
    const QString ENCRYPT_KEY = "PasswordManager2026_Key";
    int m_currentUserId;              // 当前登录用户ID

    // 核心工具函数
    bool initDatabase();              // 初始化数据库
    // 注：移除密码加密/解密函数（若无需用户登录加密，可直接删除）
    QString encrypt(const QString &plainText); // 仅保留给用户登录密码用
    QString decrypt(const QString &cipherText); // 仅保留给用户登录密码用
    void loadDataToTable(const QString &category = "全部"); // 加载当前用户数据
    void loadCategoriesToCombo();     // 加载分类
    void clearInputs();               // 清空输入框
};

#endif // MAINWINDOW_H
