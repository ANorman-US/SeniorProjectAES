#ifndef CRYPTO_H
#define CRYPTO_H
#include <array>
#include <set>
#include <mutex>

class Crypto{
    public:
        static const __uint128_t UINT128_MAX = ~__uint128_t{};
        static void encodeText(std::array<unsigned char, 16>&, const std::array<unsigned char, 16>&);//plainText XOR cipherText 
        static void genRandomSegmented(std::set<std::array<unsigned char, 16>>&, int, int);//set, size, numsegments.
        static void genRandomSegmented(std::set<std::array<unsigned char, 16>>&, int, int, std::set<std::array<unsigned char, 16>>&, std::mutex&);//set, size, numsegments, another set. to prevent duplicates between threads
        static void toCharArray(std::array<unsigned char, 16>&, const __uint128_t &);//128 bit number to char array
        static void swapBits(std::array<unsigned char, 16>&, const int &);//randomly swap n numbers of bits
        static void markovDifference(const std::array<std::array<double, 2>, 2>&, const std::array<std::array<double, 2>, 2>&, double &);//measure difference between 2 transition matrices
        static int hammingDistanceBytes(const std::array<unsigned char, 16>&, const std::array<unsigned char, 16>&);
        static int hammingDistanceBits(const std::array<unsigned char, 16>&, const std::array<unsigned char, 16>&);
};
#endif