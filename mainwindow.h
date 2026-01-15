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

// 自动生成的UI类命名空间（勾选创建界面后必有的）
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    // 构造/析构函数
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    // 按钮点击槽函数（名称必须和UI中控件的objectName匹配）
    void on_btnAdd_clicked();         // 添加账号
    void on_btnUpdate_clicked();      // 修改账号
    void on_btnDelete_clicked();      // 删除账号
    void on_btnFilter_clicked();      // 分类筛选
    void on_btnBackup_clicked();      // 备份数据
    void on_btnImport_clicked();      // 导入加密文件
    void on_btnExport_clicked();      // 导出加密文件
    void on_tableWidget_itemSelectionChanged(); // 新增：表格选中变化时触发
    void on_btnShowPassword_clicked(); // 新增：显示原密码
    void on_btnClearInputs_clicked();

private:
    Ui::MainWindow *ui;               // 指向UI界面的指针
    QSqlDatabase db;                  // SQLite数据库对象
    const QString ENCRYPT_KEY = "PasswordManager2026_Key"; // 加密密钥（可自行修改）

    // 核心工具函数
    bool initDatabase();              // 初始化数据库（创建表）
    QString encrypt(const QString &plainText); // 加密函数
    QString decrypt(const QString &cipherText); // 解密函数
    void loadDataToTable(const QString &category = "全部"); // 加载数据到表格
    void loadCategoriesToCombo();     // 加载分类到下拉框
    void clearInputs();               // 清空输入框
};

#endif // MAINWINDOW_H
