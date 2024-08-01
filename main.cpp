//Alexander Norman
//AES Crpytanalysis
#include "./headers/aes.h"
#include "./headers/huffman.h"
#include <iostream>
#include <array>
#include <set>
#include <random>
#include <chrono>
#include <thread>


using namespace std;

const int NUM_PLAINTEXTS = 100'000;
const int NUM_KEYS = 1'000'000;
const int NUM_SEGMENTS = 10;
const __uint128_t UINT128_MAX = ~__uint128_t{};

void encodeText(array<unsigned char, 16>&, const array<unsigned char, 16>&);//plainText XOR cipherText 
void genRandomSegmented(set<array<unsigned char, 16>>&, int, int);//set, size, numsegments.
void toCharArray(array<unsigned char, 16>&, const __uint128_t &);//128 bit number to char array

int main()
{
    /*
    //testing threading
    auto f = [] ()
    {
        set<array<unsigned char, 16>> setPlainTexts;
        set<array<unsigned char, 16>> setKeys;
        genRandom16(setPlainTexts, 35);
        genRandom16(setKeys, 35);
        AES aes;
        array<unsigned char, 16> state;
        for (const auto &plainText : setPlainTexts)
        {
            for(const auto &key : setKeys)
            {
                state = plainText;
                aes.encrypt(state, key);
                Huffman huffman(state);
            }
        }
    };

    auto start = chrono::high_resolution_clock::now();
    
    vector<thread> threads;
    int numThreads = 8;
    for (int i = 0; i < numThreads; i++) {
        threads.emplace_back(f);
    }
    for (auto &th : threads)
        th.join();

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cout << endl << duration.count();
    */

    /*
    //Testing Purposes
    array<unsigned char, 16> plainText = {0x19, 0xA0, 0x9A, 0xE9,
                                          0x3D, 0xF4, 0xC6, 0xF8,
                                          0xE3, 0xE2, 0x8D, 0x48,
                                          0xBE, 0x2B, 0x2A, 0x08};    
    array<unsigned char, 16> key = {0xA0, 0x88, 0x23, 0x2A,
                                    0xFA, 0x54, 0xA3, 0x6C,
                                    0xFE, 0x2C, 0x39, 0x76,
                                    0x17, 0xB1, 0x39, 0x05};                                    
    array<unsigned char, 16> state;
    state = plainText;

    //test AES class
    AES aes;
    aes.encrypt(state, key);

    //encodeText(state, plainText);

    //Huffman test
    Huffman huffman(state);
    
    for(const auto &pair : huffman.getHuffmanCodes())
    {
        cout << (int)pair.first << ": ";
        for(int i=0;i<pair.second.size();i++)
        {
            cout << pair.second[i];
        }
        cout << endl;
    }

    auto start = chrono::high_resolution_clock::now();

    set<array<unsigned char, 16>> setPlainTexts;
    set<array<unsigned char, 16>> setKeys;
    genRandom16(setPlainTexts, 1000);
    genRandom16(setKeys, 1000);

    for (const auto &pT : setPlainTexts)
    {
        for(const auto &k : setKeys)
        {
            state = pT;
            aes.encrypt(state, k);
        }
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cout << endl << duration.count();
    */




    set<array<unsigned char, 16>> setPlainTexts;
    set<array<unsigned char, 16>> setKeys;
    genRandomSegmented(setPlainTexts, 100, 10);
    genRandomSegmented(setKeys, 1000, 10);


    //update later to generate variant keys
    AES aes;
    array<unsigned char, 16> state;

    auto start = chrono::high_resolution_clock::now();

    for (const auto &plainText : setPlainTexts)
    {
        for(const auto &key : setKeys)
        {
            state = plainText;
            aes.encrypt(state, key);
            Huffman huffman(state);
            //perform markov chain analysis on huffman.getHuffmanCodes();
            //variants here later on
        }
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cout << endl << duration.count();
    


    

    return 0;
}

void encodeText(array<unsigned char, 16> &state, const array<unsigned char, 16> &plainText)
{
    for(int i=0;i<16;i++) 
        state[i] ^= plainText[i];
}

void genRandomSegmented(set<array<unsigned char, 16>> &charSet, int size, int segments)
{
    random_device rd;
    mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis64(0, ~uint64_t(0));//setting up uniform distribution for 64 bit number generation

    
    __uint128_t segmentSize = UINT128_MAX / segments;
    array<unsigned char, 16> temp;
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

void toCharArray(array<unsigned char, 16>&arr, const __uint128_t &num)
{
    __uint128_t temp = num;
    for(int i=0;i<16;i++)
    {
        arr[15 - i] = temp & 0xFF;//extract lowest 8 bits
        temp >>= 8;//bitwise shift right 8 bits
    }
}