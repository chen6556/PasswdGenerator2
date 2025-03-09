#include <fstream>
#include <streambuf>
#include <QFileDialog>
#include <QMessageBox>
#include "RSA.hpp"
#include "Dongle.hpp"
#include "MainWindow.hpp"
#include "./ui_mainwindow.h"


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), m_UI(new Ui::MainWindow),
    m_Settings("./config.ini", QSettings::Format::IniFormat)
{
    m_UI->setupUi(this);
    Init();
    LoadSetting();
}

MainWindow::~MainWindow()
{
    m_Settings.sync();
    delete m_UI;
}

void MainWindow::Init()
{
    connect(m_UI->BtnToAdvancedPage, &QPushButton::clicked, [this]() { m_UI->stackedWidget->setCurrentIndex(1); });
    connect(m_UI->BtnToMainPage, &QPushButton::clicked, [this]() { m_UI->stackedWidget->setCurrentIndex(0); });

    std::ifstream key;
    key.open(m_Settings.value("PrivateKey").toString().toStdString(), std::ios_base::binary);
    m_PrivateKey = std::string((std::istreambuf_iterator<char>(key)), std::istreambuf_iterator<char>());
    key.close();
    key.open(m_Settings.value("PublicKey").toString().toStdString(), std::ios_base::binary);
    m_PublicKey = std::string((std::istreambuf_iterator<char>(key)), std::istreambuf_iterator<char>());
    key.close();
}

void MainWindow::LoadSetting()
{
    m_UI->LdtName->setText(m_Settings.value("Name").toString());
    m_UI->LdtVersion->setText(m_Settings.value("Version").toString());
    m_UI->LdtID->setText(m_Settings.value("ID").toString());
}

void MainWindow::GenerateLicense()
{
    if (m_UI->LdtName->text().isEmpty() || m_UI->LdtVersion->text().isEmpty()
        || m_UI->LdtID->text().isEmpty() || !m_UI->LdtVersion->text().contains('.'))
    {
        return;
    }
    const QUrl path = QFileDialog::getSaveFileUrl(this, QString(), QUrl(), "*.license");
    if (path.isEmpty())
    {
        return;
    }

    QString message = m_UI->LdtName->text() + m_UI->LdtID->text();
    const QStringList list = m_UI->LdtVersion->text().split('.');
    message.append(QString("%1.%2").arg(list[0]).arg(list[1]));

    std::ofstream output(path.toLocalFile().toStdString(), std::ios_base::out | std::ios_base::binary);
    output << Dongle::ToPrintableString(RSAAlgorithm::PrivateEncrypt(message.toStdString(), m_PrivateKey));
    output.close();
}

void MainWindow::LoadPrivateKey()
{
    const QUrl path = QFileDialog::getOpenFileUrl(this, "PrivateKey");
    if (path.isEmpty())
    {
        return;
    }

    std::ifstream key(path.toLocalFile().toStdString(), std::ios_base::binary);
    m_PrivateKey = std::string((std::istreambuf_iterator<char>(key)), std::istreambuf_iterator<char>());
    key.close();
    m_Settings.setValue("PrivateKey", path.toLocalFile());
}

void MainWindow::LoadPublicKey()
{
    const QUrl path = QFileDialog::getOpenFileUrl(this, "PublicKey");
    if (path.isEmpty())
    {
        return;
    }

    std::ifstream key(path.toLocalFile().toStdString(), std::ios_base::binary);
    m_PublicKey = std::string((std::istreambuf_iterator<char>(key)), std::istreambuf_iterator<char>());
    key.close();
    m_Settings.setValue("PublicKey", path.toLocalFile());
}

void MainWindow::VerifyLicense()
{
    if (m_UI->LdtName->text().isEmpty() || m_UI->LdtVersion->text().isEmpty()
        || m_UI->LdtID->text().isEmpty() || !m_UI->LdtVersion->text().contains('.'))
    {
        return;
    }
    const QUrl path = QFileDialog::getOpenFileUrl(this, "License");
    if (path.isEmpty())
    {
        return;
    }

    QString message = m_UI->LdtName->text() + m_UI->LdtID->text();
    const QStringList list = m_UI->LdtVersion->text().split('.');
    message.append(QString("%1.%2").arg(list[0]).arg(list[1]));

    std::ifstream license(path.toLocalFile().toStdString(), std::ios_base::binary);
    const std::string licenseStr((std::istreambuf_iterator<char>(license)), std::istreambuf_iterator<char>());
    license.close();
    if (Dongle::Verify(message.toStdString(), Dongle::FromPrintableString(licenseStr), m_PublicKey))
    {
        QMessageBox::information(this, "License", "This license is valid.");
    }
    else
    {
        QMessageBox::warning(this, "License", "This license is invalid.");
    }
}

void MainWindow::GenerateKey()
{
    const QUrl path = QFileDialog::getExistingDirectoryUrl(this);
    if (path.isEmpty())
    {
        return;
    }

    std::string priKey, pubKey;
    RSAAlgorithm::GenerateKey(priKey, pubKey, m_UI->SpxBits->value());
    std::ofstream output;
    output.open((path.toLocalFile() + "/PrivateKey.txt").toStdString(), std::ios_base::out | std::ios_base::binary);
    output << priKey;
    output.close();
    output.open((path.toLocalFile() + "/PublicKey.txt").toStdString(), std::ios_base::out | std::ios_base::binary);
    output << pubKey;
    output.close();
}

void MainWindow::ReadSetting()
{
    m_Settings.setValue("Name", m_UI->LdtName->text());
    m_Settings.setValue("Version", m_UI->LdtVersion->text());
    m_Settings.setValue("ID", m_UI->LdtID->text());
}