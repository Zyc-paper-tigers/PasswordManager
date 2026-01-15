#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    // 启用高DPI适配（避免界面模糊）
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);

    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
