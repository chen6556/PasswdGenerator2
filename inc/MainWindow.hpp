#pragma once
#include <QMainWindow>
#include <QSettings>


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow;}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

private:
    Ui::MainWindow *m_UI = nullptr;
    std::string m_PrivateKey, m_PublicKey;
    QSettings m_Settings;

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    void Init();

    void LoadSetting();

private slots:
    void GenerateLicense();

    void LoadPrivateKey();

    void LoadPublicKey();

    void VerifyLicense();

    void GenerateKey();

    void ReadSetting();
};