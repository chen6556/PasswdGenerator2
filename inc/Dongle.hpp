#pragma once
#include <string>
#include <map>


class Dongle
{
private:
    std::string m_Key;
    std::string m_Code;

public:
    static const std::map<const unsigned char, const std::string> ValueToString;
    static const std::map<const std::string, const unsigned char> StringToValue;

public:
    static std::string GetUUID();

    void LoadKey(const std::string &key);

    void SetCode(const std::string &code);

    bool Verify(const std::string &message) const;

    static bool Verify(const std::string &code, const std::string &message, const std::string &key);

    static std::string ToPrintableString(const std::string &str);

    static std::string FromPrintableString(const std::string &str);
};