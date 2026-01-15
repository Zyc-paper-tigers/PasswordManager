#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(int currentUserId, QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_currentUserId(currentUserId)
{
    ui->setupUi(this);
    this->setWindowTitle(QString("个人密码管理器 - 当前用户ID：%1").arg(m_currentUserId));

    if (!initDatabase()) {
        QMessageBox::critical(this, "错误", "数据库初始化失败！\n" + db.lastError().text());
        return;
    }

    // 初始化表格
    ui->tableWidget->setColumnCount(6);
    ui->tableWidget->setHorizontalHeaderLabels({"ID", "类别", "平台", "账号", "密码（加密）", "备注"});
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);

    loadCategoriesToCombo();
    loadDataToTable();
}

MainWindow::~MainWindow()
{
    delete ui;
    if (db.isOpen()) {
        db.close();
    }
}

// 初始化数据库（用户表+密码表均明文存储）
bool MainWindow::initDatabase()
{
    db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("passwords.db");

    if (!db.open()) {
        return false;
    }

    // 创建用户表（密码明文存储）
    QSqlQuery userQuery;
    const QString createUserTable = R"(
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, -- 明文存储用户登录密码
            create_time TEXT NOT NULL
        )
    )";
    if (!userQuery.exec(createUserTable)) {
        qDebug() << "创建用户表失败：" << userQuery.lastError().text();
        return false;
    }

    // 创建密码表（密码明文存储）
    QSqlQuery pwdQuery;
    const QString createPwdTable = R"(
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            platform TEXT NOT NULL,
            account TEXT NOT NULL,
            password TEXT NOT NULL, -- 明文存储密码库密码
            remarks TEXT,
            create_time TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES user(id)
        )
    )";
    if (!pwdQuery.exec(createPwdTable)) {
        qDebug() << "创建密码表失败：" << pwdQuery.lastError().text();
        return false;
    }

    return true;
}

// 加密函数（仅用于界面显示，不影响数据库存储）
QString MainWindow::encrypt(const QString &plainText)
{
    const QString ENCRYPT_KEY = "PasswordManager2026_Key"; // 自定义加密密钥
    QByteArray keyHash = QCryptographicHash::hash(ENCRYPT_KEY.toUtf8(), QCryptographicHash::Sha256);
    QByteArray plainBytes = plainText.toUtf8();
    for (int i = 0; i < plainBytes.size(); ++i) {
        plainBytes[i] ^= keyHash[i % keyHash.size()];
    }
    return plainBytes.toBase64();
}

// 解密函数（仅用于界面显示，不影响数据库存储）
QString MainWindow::decrypt(const QString &cipherText)
{
    const QString ENCRYPT_KEY = "PasswordManager2026_Key"; // 与加密密钥一致
    QByteArray cipherBytes = QByteArray::fromBase64(cipherText.toUtf8());
    QByteArray keyHash = QCryptographicHash::hash(ENCRYPT_KEY.toUtf8(), QCryptographicHash::Sha256);
    for (int i = 0; i < cipherBytes.size(); ++i) {
        cipherBytes[i] ^= keyHash[i % keyHash.size()];
    }
    return QString(cipherBytes);
}

// 加载当前用户数据（数据库明文→表格加密显示）
void MainWindow::loadDataToTable(const QString &category)
{
    ui->tableWidget->setRowCount(0);

    QSqlQuery query;
    QString selectSql;
    if (category == "全部") {
        selectSql = QString("SELECT id, category, platform, account, password, remarks FROM passwords WHERE user_id = %1")
        .arg(m_currentUserId);
    } else {
        QString safeCategory = category;
        safeCategory.replace("'", "''");
        selectSql = QString("SELECT id, category, platform, account, password, remarks FROM passwords WHERE user_id = %1 AND category = '%2'")
                        .arg(m_currentUserId).arg(safeCategory);
    }

    if (!query.exec(selectSql)) {
        QMessageBox::warning(this, "警告", "查询数据失败！\n" + query.lastError().text());
        return;
    }

    int row = 0;
    while (query.next()) {
        ui->tableWidget->insertRow(row);
        ui->tableWidget->setItem(row, 0, new QTableWidgetItem(query.value(0).toString()));
        ui->tableWidget->setItem(row, 1, new QTableWidgetItem(query.value(1).toString()));
        ui->tableWidget->setItem(row, 2, new QTableWidgetItem(query.value(2).toString()));
        ui->tableWidget->setItem(row, 3, new QTableWidgetItem(query.value(3).toString()));

        // 数据库明文→加密后显示在表格
        QString plainPwd = query.value(4).toString();
        QString encryptedPwd = encrypt(plainPwd);
        ui->tableWidget->setItem(row, 4, new QTableWidgetItem(encryptedPwd));

        ui->tableWidget->setItem(row, 5, new QTableWidgetItem(query.value(5).toString()));
        row++;
    }
}

// 加载分类（逻辑不变）
void MainWindow::loadCategoriesToCombo()
{
    ui->comboCategory->clear();
    ui->comboCategory->addItem("全部");

    QSqlQuery query;
    QString selectSql = QString("SELECT DISTINCT category FROM passwords WHERE user_id = %1 ORDER BY category")
                            .arg(m_currentUserId);
    if (!query.exec(selectSql)) {
        QMessageBox::warning(this, "警告", "加载分类失败！\n" + query.lastError().text());
        return;
    }

    while (query.next()) {
        ui->comboCategory->addItem(query.value(0).toString());
    }
}

// 清空输入框（逻辑不变）
void MainWindow::clearInputs()
{
    ui->editCategory->clear();
    ui->editPlatform->clear();
    ui->editAccount->clear();
    ui->editPassword->clear();
    ui->editRemarks->setPlainText("");
}

// 添加账号（明文存储）
void MainWindow::on_btnAdd_clicked()
{
    const QString category = ui->editCategory->text().trimmed();
    const QString platform = ui->editPlatform->text().trimmed();
    const QString account = ui->editAccount->text().trimmed();
    const QString password = ui->editPassword->text().trimmed(); // 明文
    const QString remarks = ui->editRemarks->toPlainText().trimmed();

    if (category.isEmpty() || platform.isEmpty() || account.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "警告", "类别、平台、账号、密码不能为空！");
        return;
    }

    const QString createTime = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");

    QSqlQuery query;
    query.prepare(R"(
        INSERT INTO passwords (user_id, category, platform, account, password, remarks, create_time)
        VALUES (:user_id, :category, :platform, :account, :password, :remarks, :create_time)
    )");
    query.bindValue(":user_id", m_currentUserId);
    query.bindValue(":category", category);
    query.bindValue(":platform", platform);
    query.bindValue(":account", account);
    query.bindValue(":password", password); // 明文存储
    query.bindValue(":remarks", remarks);
    query.bindValue(":create_time", createTime);

    if (query.exec()) {
        QMessageBox::information(this, "成功", "账号添加成功！");
        clearInputs();
        loadCategoriesToCombo();
        loadDataToTable();
    } else {
        QMessageBox::warning(this, "失败", "添加失败！\n" + query.lastError().text());
    }
}

// 修改账号（明文存储）
void MainWindow::on_btnUpdate_clicked()
{
    const int selectedRow = ui->tableWidget->currentRow();
    if (selectedRow < 0) {
        QMessageBox::warning(this, "警告", "请先选中要修改的账号！");
        return;
    }

    const QString id = ui->tableWidget->item(selectedRow, 0)->text();
    const QString category = ui->editCategory->text().trimmed();
    const QString platform = ui->editPlatform->text().trimmed();
    const QString account = ui->editAccount->text().trimmed();
    const QString password = ui->editPassword->text().trimmed(); // 明文
    const QString remarks = ui->editRemarks->toPlainText().trimmed();

    if (category.isEmpty() || platform.isEmpty() || account.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "警告", "类别、平台、账号、密码不能为空！");
        return;
    }

    QSqlQuery query;
    query.prepare(R"(
        UPDATE passwords
        SET category = :category, platform = :platform, account = :account, password = :password, remarks = :remarks
        WHERE id = :id AND user_id = :user_id
    )");
    query.bindValue(":category", category);
    query.bindValue(":platform", platform);
    query.bindValue(":account", account);
    query.bindValue(":password", password); // 明文存储
    query.bindValue(":remarks", remarks);
    query.bindValue(":id", id);
    query.bindValue(":user_id", m_currentUserId);

    if (query.exec()) {
        QMessageBox::information(this, "成功", "账号修改成功！");
        clearInputs();
        loadCategoriesToCombo();
        loadDataToTable();
    } else {
        QMessageBox::warning(this, "失败", "修改失败！\n" + query.lastError().text());
    }
}

// 删除账号（逻辑不变）
void MainWindow::on_btnDelete_clicked()
{
    const int selectedRow = ui->tableWidget->currentRow();
    if (selectedRow < 0) {
        QMessageBox::warning(this, "警告", "请先选中要删除的账号！");
        return;
    }

    if (QMessageBox::question(this, "确认", "是否确定删除该账号？",
                              QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) {
        return;
    }

    const QString id = ui->tableWidget->item(selectedRow, 0)->text();
    QSqlQuery query;
    query.prepare("DELETE FROM passwords WHERE id = :id AND user_id = :user_id");
    query.bindValue(":id", id);
    query.bindValue(":user_id", m_currentUserId);

    if (query.exec()) {
        QMessageBox::information(this, "成功", "账号删除成功！");
        loadCategoriesToCombo();
        loadDataToTable();
    } else {
        QMessageBox::warning(this, "失败", "删除失败！\n" + query.lastError().text());
    }
}

// 分类筛选（逻辑不变）
void MainWindow::on_btnFilter_clicked()
{
    const QString selectedCategory = ui->comboCategory->currentText();
    loadDataToTable(selectedCategory);
}

// 备份数据库（逻辑不变）
void MainWindow::on_btnBackup_clicked()
{
    const QString backupPath = QFileDialog::getSaveFileName(this, "备份数据库",
                                                            QDateTime::currentDateTime().toString("passwords_backup_yyyyMMddHHmmss.db"),
                                                            "DB文件 (*.db)");
    if (backupPath.isEmpty()) {
        return;
    }

    db.close();
    QFile sourceFile("passwords.db");
    if (!sourceFile.copy(backupPath)) {
        QMessageBox::warning(this, "失败", "备份失败！\n" + sourceFile.errorString());
        db.open();
        return;
    }

    db.open();
    QMessageBox::information(this, "成功", "备份成功！\n路径：" + backupPath);
}

// 导出（明文导出）
void MainWindow::on_btnExport_clicked()
{
    const QString exportPath = QFileDialog::getSaveFileName(this, "导出密码文件",
                                                            QDateTime::currentDateTime().toString("passwords_export_yyyyMMddHHmmss.txt"),
                                                            "文本文件 (*.txt)");
    if (exportPath.isEmpty()) {
        return;
    }

    QSqlQuery query;
    QString selectSql = QString("SELECT category, platform, account, password, remarks FROM passwords WHERE user_id = %1")
                            .arg(m_currentUserId);
    if (!query.exec(selectSql)) {
        QMessageBox::warning(this, "警告", "查询导出数据失败！\n" + query.lastError().text());
        return;
    }

    QString exportContent;
    exportContent += "类别|平台|账号|密码|备注\n";
    while (query.next()) {
        exportContent += query.value(0).toString() + "|" +
                         query.value(1).toString() + "|" +
                         query.value(2).toString() + "|" +
                         query.value(3).toString() + "|" + // 明文导出
                         query.value(4).toString() + "\n";
    }

    QFile file(exportPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "失败", "打开导出文件失败！\n" + file.errorString());
        return;
    }

    QTextStream out(&file);
    out << exportContent;
    file.close();

    QMessageBox::information(this, "成功", "导出成功！\n路径：" + exportPath);
}

// 导入（明文导入）
void MainWindow::on_btnImport_clicked()
{
    const QString importPath = QFileDialog::getOpenFileName(this, "导入密码文件", "", "文本文件 (*.txt)");
    if (importPath.isEmpty()) {
        return;
    }

    QFile file(importPath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "失败", "打开导入文件失败！\n" + file.errorString());
        return;
    }

    QTextStream in(&file);
    QString plainContent = in.readAll();
    file.close();

    const QStringList lines = plainContent.split("\n", Qt::SkipEmptyParts);
    int successCount = 0;
    const QString createTime = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");

    for (int i = 1; i < lines.size(); ++i) {
        const QString &line = lines[i];
        const QStringList parts = line.split("|");
        if (parts.size() < 4) {
            continue;
        }

        QSqlQuery query;
        query.prepare(R"(
            INSERT INTO passwords (user_id, category, platform, account, password, remarks, create_time)
            VALUES (:user_id, :category, :platform, :account, :password, :remarks, :create_time)
        )");
        query.bindValue(":user_id", m_currentUserId);
        query.bindValue(":category", parts[0]);
        query.bindValue(":platform", parts[1]);
        query.bindValue(":account", parts[2]);
        query.bindValue(":password", parts[3]); // 明文导入
        query.bindValue(":remarks", parts.size() >=5 ? parts[4] : "");
        query.bindValue(":create_time", createTime);

        if (query.exec()) {
            successCount++;
        }
    }

    QMessageBox::information(this, "成功", QString("导入完成！\n成功导入 %1 条数据。").arg(successCount));
    loadCategoriesToCombo();
    loadDataToTable();
}

// 选中行变化（表格加密→输入框明文）
void MainWindow::on_tableWidget_itemSelectionChanged()
{
    int selectedRow = ui->tableWidget->currentRow();
    if (selectedRow < 0) {
        clearInputs();
        return;
    }

    QString category = ui->tableWidget->item(selectedRow, 1)->text();
    QString platform = ui->tableWidget->item(selectedRow, 2)->text();
    QString account = ui->tableWidget->item(selectedRow, 3)->text();
    // 表格加密密码→解密后填充输入框（输入框是密码模式，用户看不到明文）
    QString encryptedPwd = ui->tableWidget->item(selectedRow, 4)->text();
    QString plainPwd = decrypt(encryptedPwd);
    QString remarks = ui->tableWidget->item(selectedRow, 5)->text();

    ui->editCategory->setText(category);
    ui->editPlatform->setText(platform);
    ui->editAccount->setText(account);
    ui->editPassword->setText(plainPwd);
    ui->editRemarks->setPlainText(remarks);
}

// 显示原密码（直接读取数据库明文）
void MainWindow::on_btnShowPassword_clicked()
{
    int selectedRow = ui->tableWidget->currentRow();
    if (selectedRow < 0) {
        QMessageBox::warning(this, "提示", "请先选中一行数据！");
        return;
    }

    // 直接从数据库读取明文，不依赖表格加密内容
    QString pwdId = ui->tableWidget->item(selectedRow, 0)->text();
    QSqlQuery query;
    query.prepare("SELECT password FROM passwords WHERE id = :id AND user_id = :user_id");
    query.bindValue(":id", pwdId);
    query.bindValue(":user_id", m_currentUserId);

    if (query.exec() && query.next()) {
        QString plainPwd = query.value(0).toString();
        QMessageBox::information(this, "原始密码", QString("平台：%1\n账号：%2\n原始密码：%3")
                                                       .arg(ui->tableWidget->item(selectedRow, 2)->text())
                                                       .arg(ui->tableWidget->item(selectedRow, 3)->text())
                                                       .arg(plainPwd));
    } else {
        QMessageBox::warning(this, "失败", "获取原始密码失败！");
    }
}

// 一键清空输入框（逻辑不变）
void MainWindow::on_btnClearInputs_clicked()
{
    clearInputs();
}
