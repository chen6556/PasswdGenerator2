#include "RSA.hpp"
extern "C"
{
    #include <openssl/applink.c>
};
#include <openssl/rsa.h>
#include <openssl/pem.h>
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")


void RSAAlgorithm::GenerateKey(std::string &privateKey, std::string &publicKey, const int bits)
{
    int ret = 0;
    BIGNUM *bne = BN_new();
    ret = BN_set_word(bne, RSA_3);
    RSA *r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);

    BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, r, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSA_PUBKEY(pub, r);

    size_t priLen = BIO_pending(pri);
	size_t pubLen = BIO_pending(pub);
    char *priKey = new char[priLen + 1];
    char *pubKey = new char[priLen + 1];
    priKey[priLen] = pubKey[pubLen] = '\0';

    BIO_read(pri, priKey, priLen);
	BIO_read(pub, pubKey, pubLen);
    privateKey = priKey;
    publicKey = pubKey;

    BN_free(bne);
    RSA_free(r);
    BIO_free_all(pub);
	BIO_free_all(pri);
    delete priKey;
    delete pubKey;
}

void RSAAlgorithm::BindKey(const std::string &privateKey, const std::string &publicKey)
{
    m_PrivateKey = privateKey;
    m_PublicKey = publicKey;
}

std::string RSAAlgorithm::PrivateEncrypt(const std::string &message, const std::string &key)
{
    std::string encryptText;
	BIO *keyBIO = BIO_new_mem_buf(reinterpret_cast<const unsigned char *>(key.c_str()), -1);
	RSA* rsa = RSA_new();
	rsa = PEM_read_bio_RSAPrivateKey(keyBIO, &rsa, NULL, NULL);
	if (rsa == nullptr)
	{
		BIO_free_all(keyBIO);
		return encryptText;
	}

	// 获取RSA单次可以处理的数据块的最大长度
	const int keyLen = RSA_size(rsa);
	const int blockLen = keyLen - 11;    // 因为填充方式为RSA_PKCS1_PADDING,所以要在key_len基础上减去11

	// 申请内存:存贮加密后的密文数据
	char *cache = new char[keyLen + 1];
	std::memset(cache, 0, keyLen + 1);
	int ret = 0;
	std::string subStr;
	// 对数据进行分段加密(返回值是加密后数据的长度)
	for (size_t pos = 0, length = message.length(); pos < length; pos += blockLen)
    {
		subStr = message.substr(pos, blockLen);
		std::memset(cache, 0, keyLen + 1);
		ret = RSA_private_encrypt(subStr.length(), reinterpret_cast<const unsigned char *>(subStr.c_str()),
            reinterpret_cast<unsigned char *>(cache), rsa, RSA_PKCS1_PADDING);
		if (ret >= 0)
        {
			encryptText.append(std::string(cache, ret));
		}
	}

	// 释放内存
	delete cache;
	BIO_free_all(keyBIO);
	RSA_free(rsa);

	return encryptText;
}

std::string RSAAlgorithm::PrivateDecrypt(const std::string &message, const std::string &key)
{
    std::string decryptText;
	BIO *keyBIO = BIO_new_mem_buf(reinterpret_cast<const unsigned char *>(key.c_str()), -1);
	RSA* rsa = RSA_new();
	rsa = PEM_read_bio_RSAPrivateKey(keyBIO, &rsa, NULL, NULL);
	if (rsa == nullptr)
	{
		BIO_free_all(keyBIO);
		return decryptText;
	}

	// 获取RSA单次可以处理的数据块的最大长度
	const int keyLen = RSA_size(rsa);
	// 申请内存:存贮解密后的明文数据
	char *cache = new char[keyLen + 1];
	std::memset(cache, 0, keyLen + 1);
	int ret = 0;
	std::string subStr;
	// 对数据进行分段解密(返回值是解密后数据的长度)
	for (size_t pos = 0, length = message.length(); pos < length; pos += keyLen)
    {
		subStr = message.substr(pos, keyLen);
		std::memset(cache, 0, keyLen + 1);
		ret = RSA_private_decrypt(subStr.length(), reinterpret_cast<const unsigned char *>(subStr.c_str()),
            reinterpret_cast<unsigned char *>(cache), rsa, RSA_PKCS1_PADDING);
		if (ret >= 0)
        {
			decryptText.append(std::string(cache, ret));
		}
	}

	// 释放内存
	delete cache;
	BIO_free_all(keyBIO);
	RSA_free(rsa);

	return decryptText;
}

std::string RSAAlgorithm::PublicEncrypt(const std::string &message, const std::string &key)
{
    std::string encryptText;
	BIO *keyBIO = BIO_new_mem_buf(reinterpret_cast<const unsigned char *>(key.c_str()), -1);
	RSA* rsa = RSA_new();

	// 注意-------使用第1种格式的公钥进行解密
	//rsa = PEM_read_bio_RSAPublicKey(keyBIO, &rsa, NULL, NULL);
	// 注意-------使用第2种格式的公钥进行解密(我们使用这种格式作为示例)
	rsa = PEM_read_bio_RSA_PUBKEY(keyBIO, &rsa, NULL, NULL);
	if (rsa == nullptr)
	{
		BIO_free_all(keyBIO);
        return encryptText;
	}

	// 获取RSA单次处理的最大长度
	int keyLen = RSA_size(rsa);
    const int blockLen = keyLen - 11; // 因为填充方式为RSA_PKCS1_PADDING,所以要在key_len基础上减去11

	char *cache = new char[keyLen + 1];
	std::memset(cache, 0, keyLen + 1);
	int ret = 0;
	std::string subStr;
	// 对密文进行分段加密
	for (size_t pos = 0, length = message.length(); pos < length; pos += blockLen)
    {
		subStr = message.substr(pos, blockLen);
		std::memset(cache, 0, keyLen + 1);
		ret = RSA_public_encrypt(subStr.length(), reinterpret_cast<const unsigned char *>(subStr.c_str()),
            reinterpret_cast<unsigned char*>(cache), rsa, RSA_PKCS1_PADDING);
		if (ret >= 0)
        {
			encryptText.append(std::string(cache, ret));
		}
	}

	// 释放内存
	delete cache;
	BIO_free_all(keyBIO);
	RSA_free(rsa);

	return encryptText;
}

std::string RSAAlgorithm::PublicDecrypt(const std::string &message, const std::string &key)
{
    std::string decryptText;
	BIO *keyBIO = BIO_new_mem_buf(reinterpret_cast<const unsigned char *>(key.c_str()), -1);
	RSA* rsa = RSA_new();

	// 注意-------使用第1种格式的公钥进行解密
	//rsa = PEM_read_bio_RSAPublicKey(keyBIO, &rsa, NULL, NULL);
	// 注意-------使用第2种格式的公钥进行解密(我们使用这种格式作为示例)
	rsa = PEM_read_bio_RSA_PUBKEY(keyBIO, &rsa, NULL, NULL);
	if (rsa == nullptr)
	{
		BIO_free_all(keyBIO);
        return decryptText;
	}

	// 获取RSA单次处理的最大长度
	int keyLen = RSA_size(rsa);
	char *cache = new char[keyLen + 1];
	std::memset(cache, 0, keyLen + 1);
	int ret = 0;
	std::string subStr;
	// 对密文进行分段加密
	for (size_t pos = 0, length = message.length(); pos < length; pos += keyLen)
    {
		subStr = message.substr(pos, keyLen);
		std::memset(cache, 0, keyLen + 1);
		ret = RSA_public_decrypt(subStr.length(), reinterpret_cast<const unsigned char *>(subStr.c_str()),
            reinterpret_cast<unsigned char*>(cache), rsa, RSA_PKCS1_PADDING);
		if (ret >= 0)
        {
			decryptText.append(std::string(cache, ret));
		}
	}

	// 释放内存
	delete cache;
	BIO_free_all(keyBIO);
	RSA_free(rsa);

	return decryptText;
}

std::string RSAAlgorithm::PrivateEncrypt(const std::string &message) const
{
    return PrivateEncrypt(message, m_PrivateKey);
}

std::string RSAAlgorithm::PrivateDecrypt(const std::string &message) const
{
    return PrivateDecrypt(message, m_PrivateKey);
}

std::string RSAAlgorithm::PublicEncrypt(const std::string &message) const
{
    return PublicEncrypt(message, m_PublicKey);
}

std::string RSAAlgorithm::PublicDecrypt(const std::string &message) const
{
    return PublicDecrypt(message, m_PublicKey);
}

