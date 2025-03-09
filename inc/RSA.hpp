#pragma once
#include <string>


class RSAAlgorithm
{
private:
    std::string m_PrivateKey;
    std::string m_PublicKey;

public:
    static void GenerateKey(std::string &privateKey, std::string &publicKey, const int bits = 1024);

    void BindKey(const std::string &privateKey, const std::string &publicKey);
    
    static std::string PrivateEncrypt(const std::string &message, const std::string &key);

    static std::string PrivateDecrypt(const std::string &message, const std::string &key);

    static std::string PublicEncrypt(const std::string &message, const std::string &key);

    static std::string PublicDecrypt(const std::string &message, const std::string &key);

    std::string PrivateEncrypt(const std::string &message) const;

    std::string PrivateDecrypt(const std::string &message) const;

    std::string PublicEncrypt(const std::string &message) const;

    std::string PublicDecrypt(const std::string &message) const;    
};