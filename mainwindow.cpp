#include "mainwindow.h"
#include "ui_mainwindow.h"

// 构造函数：初始化界面、数据库、数据加载
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    // 初始化UI界面（勾选创建界面后自动生成的代码）
    ui->setupUi(this);
    // 设置窗口标题
    this->setWindowTitle("个人密码管理器");

    // 1. 初始化数据库
    if (!initDatabase()) {
        QMessageBox::critical(this, "错误", "数据库初始化失败！\n" + db.lastError().text());
        return;
    }

    // 2. 初始化表格（设置列数和列名）
    ui->tableWidget->setColumnCount(6);
    ui->tableWidget->setHorizontalHeaderLabels({"ID", "类别", "平台", "账号", "加密密码", "备注"});
    // 设置表格属性：整行选中、不可编辑、列宽自适应
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);

    // 3. 加载分类到下拉框
    loadCategoriesToCombo();
    // 4. 加载所有数据到表格
    loadDataToTable();
}

// 析构函数：释放UI资源、关闭数据库
MainWindow::~MainWindow()
{
    delete ui;
    if (db.isOpen()) {
        db.close();
    }
}

// -------------------------- 数据库初始化 --------------------------
bool MainWindow::initDatabase()
{
    // 连接SQLite数据库（文件保存在程序运行目录）
    db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("passwords.db");

    // 打开数据库
    if (!db.open()) {
        return false;
    }

    // 创建密码表（不存在则创建）
    QSqlQuery query;
    const QString createTableSql = R"(
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            platform TEXT NOT NULL,
            account TEXT NOT NULL,
            password TEXT NOT NULL,
            remarks TEXT,
            create_time TEXT NOT NULL
        )
    )";

    if (!query.exec(createTableSql)) {
        qDebug() << "创建表失败：" << query.lastError().text();
        return false;
    }

    return true;
}

// -------------------------- 加密函数（哈希+异或+Base64） --------------------------
QString MainWindow::encrypt(const QString &plainText)
{
    // 1. 哈希密钥（SHA256）
    QByteArray keyHash = QCryptographicHash::hash(ENCRYPT_KEY.toUtf8(), QCryptographicHash::Sha256);
    // 2. 明文转字节数组
    QByteArray plainBytes = plainText.toUtf8();
    // 3. 异或加密
    for (int i = 0; i < plainBytes.size(); ++i) {
        plainBytes[i] ^= keyHash[i % keyHash.size()];
    }
    // 4. Base64编码（避免乱码）
    return plainBytes.toBase64();
}

// -------------------------- 解密函数（反向操作） --------------------------
QString MainWindow::decrypt(const QString &cipherText)
{
    // 1. Base64解码
    QByteArray cipherBytes = QByteArray::fromBase64(cipherText.toUtf8());
    // 2. 哈希密钥
    QByteArray keyHash = QCryptographicHash::hash(ENCRYPT_KEY.toUtf8(), QCryptographicHash::Sha256);
    // 3. 异或解密
    for (int i = 0; i < cipherBytes.size(); ++i) {
        cipherBytes[i] ^= keyHash[i % keyHash.size()];
    }
    // 4. 转字符串
    return QString(cipherBytes);
}

// -------------------------- 加载数据到表格 --------------------------
void MainWindow::loadDataToTable(const QString &category)
{
    // 清空表格
    ui->tableWidget->setRowCount(0);

    // 构造查询SQL
    QSqlQuery query;
    QString selectSql;
    if (category == "全部") {
        selectSql = "SELECT id, category, platform, account, password, remarks FROM passwords";
    } else {
        QString safeCategory = category;
        safeCategory.replace("'", "''");
        selectSql = QString("SELECT id, category, platform, account, password, remarks FROM passwords WHERE category = '%1'")
                        .arg(safeCategory);
    }

    // 执行查询
    if (!query.exec(selectSql)) {
        QMessageBox::warning(this, "警告", "查询数据失败！\n" + query.lastError().text());
        return;
    }

    // 填充表格
    int row = 0;
    while (query.next()) {
        ui->tableWidget->insertRow(row);
        // 依次设置：ID、类别、平台、账号、加密密码、备注
        ui->tableWidget->setItem(row, 0, new QTableWidgetItem(query.value(0).toString()));
        ui->tableWidget->setItem(row, 1, new QTableWidgetItem(query.value(1).toString()));
        ui->tableWidget->setItem(row, 2, new QTableWidgetItem(query.value(2).toString()));
        ui->tableWidget->setItem(row, 3, new QTableWidgetItem(query.value(3).toString()));
        ui->tableWidget->setItem(row, 4, new QTableWidgetItem(query.value(4).toString()));
        ui->tableWidget->setItem(row, 5, new QTableWidgetItem(query.value(5).toString()));
        row++;
    }
}

// -------------------------- 加载分类到下拉框 --------------------------
void MainWindow::loadCategoriesToCombo()
{
    ui->comboCategory->clear();
    ui->comboCategory->addItem("全部"); // 默认选项

    // 查询所有唯一分类
    QSqlQuery query("SELECT DISTINCT category FROM passwords ORDER BY category");
    while (query.next()) {
        ui->comboCategory->addItem(query.value(0).toString());
    }
}

// -------------------------- 清空输入框 --------------------------
void MainWindow::clearInputs()
{
    ui->editCategory->clear();
    ui->editPlatform->clear();
    ui->editAccount->clear();
    ui->editPassword->clear();
    ui->editRemarks->clear();
}

// -------------------------- 按钮槽函数：添加账号 --------------------------
void MainWindow::on_btnAdd_clicked()
{
    // 1. 获取输入内容（去除首尾空格）
    const QString category = ui->editCategory->text().trimmed();
    const QString platform = ui->editPlatform->text().trimmed();
    const QString account = ui->editAccount->text().trimmed();
    const QString password = ui->editPassword->text().trimmed();
    const QString remarks = ui->editRemarks->toPlainText().trimmed();

    // 2. 输入校验
    if (category.isEmpty() || platform.isEmpty() || account.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "警告", "类别、平台、账号、密码不能为空！");
        return;
    }

    // 3. 加密密码
    const QString encryptPwd = encrypt(password);
    // 4. 获取当前时间
    const QString createTime = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");

    // 5. 插入数据到数据库
    QSqlQuery query;
    query.prepare(R"(
        INSERT INTO passwords (category, platform, account, password, remarks, create_time)
        VALUES (:category, :platform, :account, :password, :remarks, :create_time)
    )");
    // 绑定参数（防SQL注入）
    query.bindValue(":category", category);
    query.bindValue(":platform", platform);
    query.bindValue(":account", account);
    query.bindValue(":password", encryptPwd);
    query.bindValue(":remarks", remarks);
    query.bindValue(":create_time", createTime);

    // 6. 执行并反馈结果
    if (query.exec()) {
        QMessageBox::information(this, "成功", "账号添加成功！");
        clearInputs();          // 清空输入框
        loadCategoriesToCombo();// 刷新分类下拉框
        loadDataToTable();      // 刷新表格
    } else {
        QMessageBox::warning(this, "失败", "添加失败！\n" + query.lastError().text());
    }
}

// -------------------------- 按钮槽函数：修改账号 --------------------------
void MainWindow::on_btnUpdate_clicked()
{
    // 1. 检查是否选中行
    const int selectedRow = ui->tableWidget->currentRow();
    if (selectedRow < 0) {
        QMessageBox::warning(this, "警告", "请先选中要修改的账号！");
        return;
    }

    // 2. 获取选中行的ID
    const QString id = ui->tableWidget->item(selectedRow, 0)->text();
    // 3. 获取输入内容
    const QString category = ui->editCategory->text().trimmed();
    const QString platform = ui->editPlatform->text().trimmed();
    const QString account = ui->editAccount->text().trimmed();
    const QString password = ui->editPassword->text().trimmed();
    const QString remarks = ui->editRemarks->toPlainText().trimmed();

    // 4. 输入校验
    if (category.isEmpty() || platform.isEmpty() || account.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "警告", "类别、平台、账号、密码不能为空！");
        return;
    }

    // 5. 加密新密码
    const QString encryptPwd = encrypt(password);

    // 6. 更新数据
    QSqlQuery query;
    query.prepare(R"(
        UPDATE passwords
        SET category = :category, platform = :platform, account = :account, password = :password, remarks = :remarks
        WHERE id = :id
    )");
    query.bindValue(":category", category);
    query.bindValue(":platform", platform);
    query.bindValue(":account", account);
    query.bindValue(":password", encryptPwd);
    query.bindValue(":remarks", remarks);
    query.bindValue(":id", id);

    // 7. 执行并反馈
    if (query.exec()) {
        QMessageBox::information(this, "成功", "账号修改成功！");
        clearInputs();
        loadCategoriesToCombo();
        loadDataToTable();
    } else {
        QMessageBox::warning(this, "失败", "修改失败！\n" + query.lastError().text());
    }
}

// -------------------------- 按钮槽函数：删除账号 --------------------------
void MainWindow::on_btnDelete_clicked()
{
    // 1. 检查选中行
    const int selectedRow = ui->tableWidget->currentRow();
    if (selectedRow < 0) {
        QMessageBox::warning(this, "警告", "请先选中要删除的账号！");
        return;
    }

    // 2. 确认删除
    if (QMessageBox::question(this, "确认", "是否确定删除该账号？",
                              QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) {
        return;
    }

    // 3. 获取ID并删除
    const QString id = ui->tableWidget->item(selectedRow, 0)->text();
    QSqlQuery query;
    query.prepare("DELETE FROM passwords WHERE id = :id");
    query.bindValue(":id", id);

    // 4. 执行并反馈
    if (query.exec()) {
        QMessageBox::information(this, "成功", "账号删除成功！");
        loadCategoriesToCombo();
        loadDataToTable();
    } else {
        QMessageBox::warning(this, "失败", "删除失败！\n" + query.lastError().text());
    }
}

// -------------------------- 按钮槽函数：分类筛选 --------------------------
void MainWindow::on_btnFilter_clicked()
{
    const QString selectedCategory = ui->comboCategory->currentText();
    loadDataToTable(selectedCategory);
}

// -------------------------- 按钮槽函数：备份数据库 --------------------------
void MainWindow::on_btnBackup_clicked()
{
    // 1. 选择备份路径
    const QString backupPath = QFileDialog::getSaveFileName(this, "备份数据库",
                                                            QDateTime::currentDateTime().toString("passwords_backup_yyyyMMddHHmmss.db"),
                                                            "DB文件 (*.db)");
    if (backupPath.isEmpty()) {
        return;
    }

    // 2. 关闭数据库（避免文件被占用）
    db.close();

    // 3. 复制数据库文件
    QFile sourceFile("passwords.db");
    if (!sourceFile.copy(backupPath)) {
        QMessageBox::warning(this, "失败", "备份失败！\n" + sourceFile.errorString());
        db.open(); // 重新打开数据库
        return;
    }

    // 4. 重新打开数据库并反馈
    db.open();
    QMessageBox::information(this, "成功", "备份成功！\n路径：" + backupPath);
}

// -------------------------- 按钮槽函数：导出加密文件 --------------------------
void MainWindow::on_btnExport_clicked()
{
    // 1. 选择导出路径
    const QString exportPath = QFileDialog::getSaveFileName(this, "导出加密文件",
                                                            QDateTime::currentDateTime().toString("passwords_export_yyyyMMddHHmmss.enc"),
                                                            "加密文件 (*.enc)");
    if (exportPath.isEmpty()) {
        return;
    }

    // 2. 查询所有数据并拼接
    QSqlQuery query("SELECT category, platform, account, password, remarks FROM passwords");
    QString exportContent;
    while (query.next()) {
        exportContent += query.value(0).toString() + "|" +
                         query.value(1).toString() + "|" +
                         query.value(2).toString() + "|" +
                         query.value(3).toString() + "|" +
                         query.value(4).toString() + "\n";
    }

    // 3. 加密导出内容
    const QString encryptContent = encrypt(exportContent);

    // 4. 写入文件
    QFile file(exportPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "失败", "打开导出文件失败！\n" + file.errorString());
        return;
    }

    QTextStream out(&file);
    out << encryptContent;
    file.close();

    // 5. 反馈结果
    QMessageBox::information(this, "成功", "导出成功！\n路径：" + exportPath);
}

// -------------------------- 按钮槽函数：导入加密文件 --------------------------
void MainWindow::on_btnImport_clicked()
{
    // 1. 选择导入文件
    const QString importPath = QFileDialog::getOpenFileName(this, "导入加密文件", "", "加密文件 (*.enc)");
    if (importPath.isEmpty()) {
        return;
    }

    // 2. 读取文件内容
    QFile file(importPath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "失败", "打开导入文件失败！\n" + file.errorString());
        return;
    }

    QTextStream in(&file);
    const QString encryptContent = in.readAll();
    file.close();

    // 3. 解密内容
    const QString plainContent = decrypt(encryptContent);
    if (plainContent.isEmpty()) {
        QMessageBox::warning(this, "失败", "解密失败！密钥错误或文件损坏。");
        return;
    }

    // 4. 解析并插入数据
    const QStringList lines = plainContent.split("\n", Qt::SkipEmptyParts);
    int successCount = 0;
    const QString createTime = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");

    for (const QString &line : lines) {
        const QStringList parts = line.split("|");
        if (parts.size() < 4) { // 至少包含：类别、平台、账号、加密密码
            continue;
        }

        QSqlQuery query;
        query.prepare(R"(
            INSERT INTO passwords (category, platform, account, password, remarks, create_time)
            VALUES (:category, :platform, :account, :password, :remarks, :create_time)
        )");
        query.bindValue(":category", parts[0]);
        query.bindValue(":platform", parts[1]);
        query.bindValue(":account", parts[2]);
        query.bindValue(":password", parts[3]);
        query.bindValue(":remarks", parts.size() >=5 ? parts[4] : "");
        query.bindValue(":create_time", createTime);

        if (query.exec()) {
            successCount++;
        }
    }

    // 5. 反馈结果
    QMessageBox::information(this, "成功", QString("导入完成！\n成功导入 %1 条数据。").arg(successCount));
    loadCategoriesToCombo();
    loadDataToTable();
}

// 表格选中行变化时，自动填充左侧输入框
void MainWindow::on_tableWidget_itemSelectionChanged()
{
    // 获取当前选中的行号
    int selectedRow = ui->tableWidget->currentRow();
    if (selectedRow < 0) {
        return; // 没有选中行，直接返回
    }

    // 从表格中获取选中行的每一列数据
    QString category = ui->tableWidget->item(selectedRow, 1)->text();
    QString platform = ui->tableWidget->item(selectedRow, 2)->text();
    QString account = ui->tableWidget->item(selectedRow, 3)->text();
    QString password = ui->tableWidget->item(selectedRow, 4)->text();
    QString remarks = ui->tableWidget->item(selectedRow, 5)->text();

    // 填充到左侧对应的输入框
    ui->editCategory->setText(category);
    ui->editPlatform->setText(platform);
    ui->editAccount->setText(account);
    ui->editPassword->setText(password); // 显示加密后的密码
    ui->editRemarks->setPlainText(remarks); // 备注用QTextEdit的setPlainText
}

// 显示选中行的原始密码（解密后）
void MainWindow::on_btnShowPassword_clicked()
{
    // 获取当前选中的行
    int selectedRow = ui->tableWidget->currentRow();
    if (selectedRow < 0) {
        QMessageBox::warning(this, "提示", "请先选中一行数据！");
        return;
    }

    // 从表格中获取加密后的密码
    QString encryptedPwd = ui->tableWidget->item(selectedRow, 4)->text();
    // 解密得到原始密码
    QString plainPwd = decrypt(encryptedPwd);

    // 用弹窗显示原密码（比直接显示在输入框更安全）
    QMessageBox::information(this, "原始密码", QString("平台：%1\n账号：%2\n原始密码：%3")
                                                   .arg(ui->tableWidget->item(selectedRow, 2)->text())
                                                   .arg(ui->tableWidget->item(selectedRow, 3)->text())
                                                   .arg(plainPwd));
}
