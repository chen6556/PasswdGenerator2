#include <sstream>
#include <fstream>
#include "Dongle.hpp"
#include "RSA.hpp"
#include <openssl/comp.h>


#ifdef __linux__

std::string Dongle::GetUUID()
{
    char buf_ps[48] = {'\0'};
    char cmd[] = "sudo dmidecode -s system-uuid";
    FILE *f;
    if( (f = popen(cmd, "r")) != NULL)
    {
        fgets(buf_ps, 48, f);
        fgets(buf_ps, 48, f);
        pclose(f);
        f = NULL;
    }
    for (size_t i = 0; i < 48; ++i)
    {
        if (buf_ps[i] == ' ' || buf_ps[i] == '\r' || buf_ps[i] == '\n')
        {
            buf_ps[i] = '\0';
            break;
        }
    }
    return std::string(buf_ps);
}

#elif _WIN32

std::string Dongle::GetUUID()
{
    char buf_ps[48] = {'\0'};
    char cmd[] = "wmic csproduct get uuid";
    FILE *f;
    if( (f = _popen(cmd, "r")) != NULL)
    {
        fgets(buf_ps, 48, f);
        fgets(buf_ps, 48, f);
        _pclose(f);
        f = NULL;
    }
    for (size_t i = 0; i < 48; ++i)
    {
        if (buf_ps[i] == ' ' || buf_ps[i] == '\r' || buf_ps[i] == '\n')
        {
            buf_ps[i] = '\0';
            break;
        }
    }
    return std::string(buf_ps);
}

#endif


const std::map<const unsigned char, const std::string> Dongle::ValueToString =
    {{0, "00"}, {1, "01"}, {2, "02"}, {3, "03"}, {4, "04"}, {5, "05"}, {6, "06"}, {7, "07"},
    {8, "08"}, {9, "09"}, {10, "0A"}, {11, "0B"}, {12, "0C"}, {13, "0D"}, {14, "0E"}, {15, "0F"},
    {16, "10"}, {17, "11"}, {18, "12"}, {19, "13"}, {20, "14"}, {21, "15"}, {22, "16"}, {23, "17"},
    {24, "18"}, {25, "19"}, {26, "1A"}, {27, "1B"}, {28, "1C"}, {29, "1D"}, {30, "1E"}, {31, "1F"},
    {32, "20"}, {33, "21"}, {34, "22"}, {35, "23"}, {36, "24"}, {37, "25"}, {38, "26"}, {39, "27"},
    {40, "28"}, {41, "29"}, {42, "2A"}, {43, "2B"}, {44, "2C"}, {45, "2D"}, {46, "2E"}, {47, "2F"},
    {48, "30"}, {49, "31"}, {50, "32"}, {51, "33"}, {52, "34"}, {53, "35"}, {54, "36"}, {55, "37"},
    {56, "38"}, {57, "39"}, {58, "3A"}, {59, "3B"}, {60, "3C"}, {61, "3D"}, {62, "3E"}, {63, "3F"},
    {64, "40"}, {65, "41"}, {66, "42"}, {67, "43"}, {68, "44"}, {69, "45"}, {70, "46"}, {71, "47"},
    {72, "48"}, {73, "49"}, {74, "4A"}, {75, "4B"}, {76, "4C"}, {77, "4D"}, {78, "4E"}, {79, "4F"},
    {80, "50"}, {81, "51"}, {82, "52"}, {83, "53"}, {84, "54"}, {85, "55"}, {86, "56"}, {87, "57"},
    {88, "58"}, {89, "59"}, {90, "5A"}, {91, "5B"}, {92, "5C"}, {93, "5D"}, {94, "5E"}, {95, "5F"},
    {96, "60"}, {97, "61"}, {98, "62"}, {99, "63"}, {100, "64"}, {101, "65"}, {102, "66"}, {103, "67"},
    {104, "68"}, {105, "69"}, {106, "6A"}, {107, "6B"}, {108, "6C"}, {109, "6D"}, {110, "6E"}, {111, "6F"},
    {112, "70"}, {113, "71"}, {114, "72"}, {115, "73"}, {116, "74"}, {117, "75"}, {118, "76"}, {119, "77"},
    {120, "78"}, {121, "79"}, {122, "7A"}, {123, "7B"}, {124, "7C"}, {125, "7D"}, {126, "7E"}, {127, "7F"},
    {128, "80"}, {129, "81"}, {130, "82"}, {131, "83"}, {132, "84"}, {133, "85"}, {134, "86"}, {135, "87"},
    {136, "88"}, {137, "89"}, {138, "8A"}, {139, "8B"}, {140, "8C"}, {141, "8D"}, {142, "8E"}, {143, "8F"},
    {144, "90"}, {145, "91"}, {146, "92"}, {147, "93"}, {148, "94"}, {149, "95"}, {150, "96"}, {151, "97"},
    {152, "98"}, {153, "99"}, {154, "9A"}, {155, "9B"}, {156, "9C"}, {157, "9D"}, {158, "9E"}, {159, "9F"},
    {160, "A0"}, {161, "A1"}, {162, "A2"}, {163, "A3"}, {164, "A4"}, {165, "A5"}, {166, "A6"}, {167, "A7"},
    {168, "A8"}, {169, "A9"}, {170, "AA"}, {171, "AB"}, {172, "AC"}, {173, "AD"}, {174, "AE"}, {175, "AF"},
    {176, "B0"}, {177, "B1"}, {178, "B2"}, {179, "B3"}, {180, "B4"}, {181, "B5"}, {182, "B6"}, {183, "B7"},
    {184, "B8"}, {185, "B9"}, {186, "BA"}, {187, "BB"}, {188, "BC"}, {189, "BD"}, {190, "BE"}, {191, "BF"},
    {192, "C0"}, {193, "C1"}, {194, "C2"}, {195, "C3"}, {196, "C4"}, {197, "C5"}, {198, "C6"}, {199, "C7"},
    {200, "C8"}, {201, "C9"}, {202, "CA"}, {203, "CB"}, {204, "CC"}, {205, "CD"}, {206, "CE"}, {207, "CF"},
    {208, "D0"}, {209, "D1"}, {210, "D2"}, {211, "D3"}, {212, "D4"}, {213, "D5"}, {214, "D6"}, {215, "D7"},
    {216, "D8"}, {217, "D9"}, {218, "DA"}, {219, "DB"}, {220, "DC"}, {221, "DD"}, {222, "DE"}, {223, "DF"},
    {224, "E0"}, {225, "E1"}, {226, "E2"}, {227, "E3"}, {228, "E4"}, {229, "E5"}, {230, "E6"}, {231, "E7"},
    {232, "E8"}, {233, "E9"}, {234, "EA"}, {235, "EB"}, {236, "EC"}, {237, "ED"}, {238, "EE"}, {239, "EF"},
    {240, "F0"}, {241, "F1"}, {242, "F2"}, {243, "F3"}, {244, "F4"}, {245, "F5"}, {246, "F6"}, {247, "F7"},
    {248, "F8"}, {249, "F9"}, {250, "FA"}, {251, "FB"}, {252, "FC"}, {253, "FD"}, {254, "FE"}, {255, "FF"}};

const std::map<const std::string, const unsigned char> Dongle::StringToValue =
    {{"00", 0}, {"01", 1}, {"02", 2}, {"03", 3}, {"04", 4}, {"05", 5}, {"06", 6}, {"07", 7},
    {"08", 8}, {"09", 9}, {"0A", 10}, {"0B", 11}, {"0C", 12}, {"0D", 13}, {"0E", 14}, {"0F", 15},
    {"10", 16}, {"11", 17}, {"12", 18}, {"13", 19}, {"14", 20}, {"15", 21}, {"16", 22}, {"17", 23},
    {"18", 24}, {"19", 25}, {"1A", 26}, {"1B", 27}, {"1C", 28}, {"1D", 29}, {"1E", 30}, {"1F", 31},
    {"20", 32}, {"21", 33}, {"22", 34}, {"23", 35}, {"24", 36}, {"25", 37}, {"26", 38}, {"27", 39},
    {"28", 40}, {"29", 41}, {"2A", 42}, {"2B", 43}, {"2C", 44}, {"2D", 45}, {"2E", 46}, {"2F", 47},
    {"30", 48}, {"31", 49}, {"32", 50}, {"33", 51}, {"34", 52}, {"35", 53}, {"36", 54}, {"37", 55},
    {"38", 56}, {"39", 57}, {"3A", 58}, {"3B", 59}, {"3C", 60}, {"3D", 61}, {"3E", 62}, {"3F", 63},
    {"40", 64}, {"41", 65}, {"42", 66}, {"43", 67}, {"44", 68}, {"45", 69}, {"46", 70}, {"47", 71},
    {"48", 72}, {"49", 73}, {"4A", 74}, {"4B", 75}, {"4C", 76}, {"4D", 77}, {"4E", 78}, {"4F", 79},
    {"50", 80}, {"51", 81}, {"52", 82}, {"53", 83}, {"54", 84}, {"55", 85}, {"56", 86}, {"57", 87},
    {"58", 88}, {"59", 89}, {"5A", 90}, {"5B", 91}, {"5C", 92}, {"5D", 93}, {"5E", 94}, {"5F", 95},
    {"60", 96}, {"61", 97}, {"62", 98}, {"63", 99}, {"64", 100}, {"65", 101}, {"66", 102}, {"67", 103},
    {"68", 104}, {"69", 105}, {"6A", 106}, {"6B", 107}, {"6C", 108}, {"6D", 109}, {"6E", 110}, {"6F", 111},
    {"70", 112}, {"71", 113}, {"72", 114}, {"73", 115}, {"74", 116}, {"75", 117}, {"76", 118}, {"77", 119},
    {"78", 120}, {"79", 121}, {"7A", 122}, {"7B", 123}, {"7C", 124}, {"7D", 125}, {"7E", 126}, {"7F", 127},
    {"80", 128}, {"81", 129}, {"82", 130}, {"83", 131}, {"84", 132}, {"85", 133}, {"86", 134}, {"87", 135},
    {"88", 136}, {"89", 137}, {"8A", 138}, {"8B", 139}, {"8C", 140}, {"8D", 141}, {"8E", 142}, {"8F", 143},
    {"90", 144}, {"91", 145}, {"92", 146}, {"93", 147}, {"94", 148}, {"95", 149}, {"96", 150}, {"97", 151},
    {"98", 152}, {"99", 153}, {"9A", 154}, {"9B", 155}, {"9C", 156}, {"9D", 157}, {"9E", 158}, {"9F", 159},
    {"A0", 160}, {"A1", 161}, {"A2", 162}, {"A3", 163}, {"A4", 164}, {"A5", 165}, {"A6", 166}, {"A7", 167},
    {"A8", 168}, {"A9", 169}, {"AA", 170}, {"AB", 171}, {"AC", 172}, {"AD", 173}, {"AE", 174}, {"AF", 175},
    {"B0", 176}, {"B1", 177}, {"B2", 178}, {"B3", 179}, {"B4", 180}, {"B5", 181}, {"B6", 182}, {"B7", 183},
    {"B8", 184}, {"B9", 185}, {"BA", 186}, {"BB", 187}, {"BC", 188}, {"BD", 189}, {"BE", 190}, {"BF", 191},
    {"C0", 192}, {"C1", 193}, {"C2", 194}, {"C3", 195}, {"C4", 196}, {"C5", 197}, {"C6", 198}, {"C7", 199},
    {"C8", 200}, {"C9", 201}, {"CA", 202}, {"CB", 203}, {"CC", 204}, {"CD", 205}, {"CE", 206}, {"CF", 207},
    {"D0", 208}, {"D1", 209}, {"D2", 210}, {"D3", 211}, {"D4", 212}, {"D5", 213}, {"D6", 214}, {"D7", 215},
    {"D8", 216}, {"D9", 217}, {"DA", 218}, {"DB", 219}, {"DC", 220}, {"DD", 221}, {"DE", 222}, {"DF", 223},
    {"E0", 224}, {"E1", 225}, {"E2", 226}, {"E3", 227}, {"E4", 228}, {"E5", 229}, {"E6", 230}, {"E7", 231},
    {"E8", 232}, {"E9", 233}, {"EA", 234}, {"EB", 235}, {"EC", 236}, {"ED", 237}, {"EE", 238}, {"EF", 239},
    {"F0", 240}, {"F1", 241}, {"F2", 242}, {"F3", 243}, {"F4", 244}, {"F5", 245}, {"F6", 246}, {"F7", 247},
    {"F8", 248}, {"F9", 249}, {"FA", 250}, {"FB", 251}, {"FC", 252}, {"FD", 253}, {"FE", 254}, {"FF", 255}};


void Dongle::LoadKey(const std::string &key)
{
    m_Key = key;
}

void Dongle::SetCode(const std::string &code)
{
    m_Code = code;
}

bool Dongle::Verify(const std::string &message) const
{
    return m_Code == RSAAlgorithm::PublicDecrypt(message, m_Key);
}

bool Dongle::Verify(const std::string &code, const std::string &message, const std::string &key)
{
    return code == RSAAlgorithm::PublicDecrypt(message, key);
}

std::string Dongle::ToPrintableString(const std::string &str)
{
	std::string result;
	for (const char c : str)
	{
		result.append(ValueToString.at(c));
	}
	return result;
}

std::string Dongle::FromPrintableString(const std::string &str)
{
	std::string result, key("00");
	for (size_t i = 0, count = str.length(); i < count; ++i)
	{
		key[0] = str[i];
		key[1] = str[++i];
		result.push_back(StringToValue.at(key));
	}
	return result;
}