#include <iostream>
#include <string>
#include <vector>

template <typename T>

T LeftShift(T value, int pos)
{
    const int bit = sizeof(T) * 8;
    return (value << pos) | (value >> (bit - pos));
}


unsigned int FuncNLin(int i, unsigned int B, unsigned int C, unsigned int D)
{
    unsigned int result;

    if (0 <= i && i <= 19)
    {
        result = (B & C) | ((~B) & D);
    }

    else if (20 <= i && i <= 39)
    {
        result = B ^ C ^ D;
    }

    else if (40 <= i && i <= 59)
    {
        result = (B & C) | (B & D) | (C & D);
    }

    else if (60 <= i && i <= 79)
    {
        result = B ^ C ^ D;
    }

    return result;
}


std::string SHA_1(std::string m)
{
    std::vector<bool> mBits;

    for (int i = 0; i < m.size(); i++)
    {
        for (int j = 7; j >= 0; j--)
        {
            mBits.push_back(m[i] & (1 << j));
        }
    }

    unsigned int H0 = 0x67452301;
    unsigned int H1 = 0xEFCDAB89;
    unsigned int H2 = 0x98BADCFE;
    unsigned int H3 = 0x10325476;
    unsigned int H4 = 0xC3D2E1F0;

    unsigned int K[80];

    for (int i = 0; i <= 79; ++i)
    {
        if (0 <= i && i <= 19)
        {
            K[i] = 0x5A827999;
        }

        else if (20 <= i && i <= 39)
        {
            K[i] = 0x6ED9EBA1;
        }

        else if (40 <= i && i <= 59)
        {
            K[i] = 0x8F1BBCDC;
        }

        else if (60 <= i && i <= 79)
        {
            K[i] = 0xCA62C1D6;
        }
    }

    long long messageLength = mBits.size();

    bool flag = true;

    while (mBits.size() % 512 != 448)
    {
        if (flag)
        {
            mBits.push_back(true);
            flag = false;
        }

        else
        {
            mBits.push_back(false);
        }
    }

    for (int i = 63; i >= 0; --i)
    {
        mBits.push_back((messageLength & (1LL << i)) != 0);
    }


    for (int i = 0; i < mBits.size(); i += 512)
    {
        unsigned int A;
        unsigned int B;
        unsigned int C;
        unsigned int D;
        unsigned int E;

        unsigned int W[80] = { 0 };
        int k = 0;

        for (int j = i; j < i + 512; j += 32)
        {
            int p = 0;

            for (int t = j; t < j + 32; ++t)
            {
                W[k] |= (static_cast<unsigned int>(mBits[t]) << p);
                ++p;
            }
            ++k;
        }

        for (int j = 16; j <= 79; ++j)
        {
            W[j] = LeftShift(W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16], 1);
        }

        A = H0;
        B = H1;
        C = H2;
        D = H3;
        E = H4;

        for (int j = 0; j <= 79; ++j)
        {
            unsigned int temp = LeftShift(A, 5) + FuncNLin(j, B, C, D) + E + W[j] + K[j];
            E = D;
            D = C;
            C = LeftShift(B, 30);
            B = A;
            A = temp;
        }

        H0 += A;
        H1 += B;
        H2 += C;
        H3 += D;
        H4 += E;
    }

    char newMessage[41];
    sprintf_s(newMessage, "%08x%08x%08x%08x%08x", H0, H1, H2, H3, H4);
    return std::string(newMessage);
}


int main()
{
    std::string s = "abcd";
    std::cout << "original : " << s << std::endl;
    std::cout << "SHA-1 : " << SHA_1(s) << std::endl;

    return 0;
}