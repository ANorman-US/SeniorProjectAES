#include "../headers/crypto.h"
#include <cmath>
#include <random>

void Crypto::encodeText(std::array<unsigned char, 16> &state, const std::array<unsigned char, 16> &plainText)
{
    for(int i=0;i<16;i++) 
        state[i] ^= plainText[i];
}

void Crypto::markovDifference(const std::array<std::array<double, 2>, 2>&mControl, const std::array<std::array<double, 2>, 2>&mVariant, double &difference)
{
    double total = 0;
    for(int i=0;i<2;i++)
    {
        for(int j=0;j<2;j++)
        {
            double d = mControl[i][j] - mVariant[i][j];
            total += (d*d);
        }
    }
    difference = std::sqrt(total);
}

void Crypto::swapBits(std::array<unsigned char, 16>&key, const int &num)
{
    if(num != 128)//1 to 64 bits flipped
    {
        std::set<int> indices;//makes sure no duplicates of flipping
        for(int i=0;i<num;i++)
        {
            int index = rand() % 128;
            while(indices.count(index))
                index = rand() % 128;
            indices.insert(index);
            

            int byteIndex = index / 8;
            int bitIndex = index % 8;

            unsigned char c = 1 << bitIndex;//creates a byte with a 1 at the index
            key[byteIndex] ^= c;//XOR only affects targeted index
        }
    }
    else//flip all 128 bits
    {
        for(int i=0;i<128;i++)
        {
            int byteIndex = i / 8;
            int bitIndex = i % 8;
            unsigned char c = 1 << bitIndex;
            key[byteIndex] ^= c;
        }
    }
}

void Crypto::genRandomSegmented(std::set<std::array<unsigned char, 16>> &charSet, int size, int segments)
{
    std::random_device seed;//seed for random number generator
    std::mt19937_64 gen(seed());//random number generator
    std::uniform_int_distribution<uint64_t> dis64(0, ~uint64_t(0));//setting up uniform distribution for 64 bit number generation

    
    __uint128_t segmentSize = UINT128_MAX / segments;
    std::array<unsigned char, 16> temp;
    __int128_t num;
    int index = 0;//keeps track of the segment we are working in. Higher end segments may have 1 less instance than lower end segments
    while(charSet.size() < size)
    {
        num = (dis64(gen)) << 64 | dis64(gen);//generates 2 64 bit numbers and combines
        num = (num % segmentSize) + (index * segmentSize);//ensures it falls in the range
    
        toCharArray(temp, num);//convert 128 bit number to the array
        bool added = charSet.insert(temp).second;//prevents advancing to the next segment in case of duplicate
        if(added)
        {
            index++;
            if(index == segments)
                index = 0;
        }
    }
}

void Crypto::genRandomSegmented(std::set<std::array<unsigned char, 16>> &charSet, int size, int segments, std::set<std::array<unsigned char, 16>> &totalSet, std::mutex &m2)//for use with keys only in threads
{
    std::random_device seed;//seed for random number generator
    std::mt19937_64 gen(seed());//random number generator
    std::uniform_int_distribution<uint64_t> dis64(0, ~uint64_t(0));//setting up uniform distribution for 64 bit number generation

    
    __uint128_t segmentSize = UINT128_MAX / segments;
    std::array<unsigned char, 16> temp;
    __int128_t num;
    int index = 0;//keeps track of the segment we are working in. Higher end segments may have 1 less instance than lower end segments
    while(charSet.size() < size)
    {
        num = (dis64(gen)) << 64 | dis64(gen);//generates 2 64 bit numbers and combines
        num = (num % segmentSize) + (index * segmentSize);//ensures it falls in the range
    
        toCharArray(temp, num);//convert 128 bit number to the array
        m2.lock();
        bool added = totalSet.insert(temp).second;//prevents advancing to the next segment in case of duplicate in total set
        m2.unlock();
        if(added)
        {
            charSet.insert(temp);//add to local set
            index++;
            if(index == segments)
                index = 0;
        }
    }
}

void Crypto::toCharArray(std::array<unsigned char, 16>&arr, const __uint128_t &num)
{
    __uint128_t temp = num;
    for(int i=0;i<16;i++)
    {
        arr[15 - i] = temp & 0xFF;//extract lowest 8 bits
        temp >>= 8;//bitwise shift right 8 bits
    }
}

int Crypto::hammingDistanceBytes(const std::array<unsigned char, 16>&textOne, const std::array<unsigned char, 16>&textTwo)
{
    int distance = 0;
    for(int i=0;i<16;i++)
    {
        if(textOne[i] != textTwo[i])
            distance++;
    }
    return distance;
}

int Crypto::hammingDistanceBits(const std::array<unsigned char, 16>&textOne, const std::array<unsigned char, 16>&textTwo)
{
    int distance = 0;
    for(int i=0;i<16;i++)
    {
        unsigned char b1 = textOne[i];
        unsigned char b2 = textTwo[i];
        for(int j=7; j>=0;j--)
        {
            unsigned char c1 = (b1 >> j) & 1;
            unsigned char c2 = (b2 >> j) & 1;
            if(c1 != c2)
                distance++;
        }
    }
    return distance;
}