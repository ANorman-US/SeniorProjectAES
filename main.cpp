//Alexander Norman
//AES Crpytanalysis
//Notes
//16-17s without threading, 100 plaintexts, 1000 keys
//4 seconds with 6  threads, 100 plainTexts, 996 keys, 99,600 iterations
//3.4 seconds with 8 threads, 100 pT, 1000 keys, 100,000 iterations
//2.88 seconds with 10 threads, 100Pt, 1000 keys, 100,000 iterations
//294 seconds with 10 threads, 1,000pT, 10,000 keys, 10,000,000 iterations //bugged
/*
0.154673
0.166432
0.178436
0.18461
0.188433
0.190568
0.191298
0.191448
*/
//356 seconds with 10 threads, 1,000pT, 10,000 keys, 10,000,000 iterations //fixed
/*
1 bit difference 0.154903
2 bit difference 0.168106
4 bit difference 0.179299
8 bit difference 0.185454
16 bit difference 0.189332
32 bit difference 0.191303
64 bit difference 0.191789
128 bit difference 0.0880248
*/
/*Preliminary testing with other bit differences
96 bit difference .18524
112 bit difference .181131
120 bit difference .168098
124 bit difference .161086
126 bit difference .163463
127 bit difference .162243
*/
/*
11066.5 seconds
100000000 iterations

0.155227
0.168306
0.179363
0.185552
0.189404
0.191373
0.191859
0.19136
0.189376
0.185637
0.18001
0.171311
0.161956
0.0880348
*/
#include "./headers/aes.h"
#include "./headers/huffman.h"
#include "./headers/markov.h"
#include <iostream>
#include <array>
#include <set>
#include <random>
#include <cmath>
#include <chrono>
#include <thread>
#include <mutex>

using namespace std;

//const int NUM_PLAINTEXTS = 100'000;
//const int NUM_KEYS = 1'000'000;
const int NUM_PLAINTEXTS = 1'00;
const int NUM_KEYS = 100'0;
const int NUM_SEGMENTS = 10;
const int NUM_THREADS = 10;
const __uint128_t UINT128_MAX = ~__uint128_t{};

//# of bits being altered in variant keys
const int variantBitLength = 14;
const array<int, variantBitLength> variantBits = {1,2,4,8,16,32,64,96,112,120,124,126,127,128};

mutex m;

void encodeText(array<unsigned char, 16>&, const array<unsigned char, 16>&);//plainText XOR cipherText 
void genRandomSegmented(set<array<unsigned char, 16>>&, int, int);//set, size, numsegments.
void genRandomSegmented2(set<array<unsigned char, 16>>&, int, int, set<array<unsigned char, 16>>&);//set, size, numsegments, another set. to prevent duplicates between threads
void toCharArray(array<unsigned char, 16>&, const __uint128_t &);//128 bit number to char array
void swapBits(array<unsigned char, 16>&, const int &);//randomly swap n numbers of bits
void markovDifference(const array<array<double, 2>, 2>&, const array<array<double, 2>, 2>&, double &);//measure difference between 2 transition matrices

void threadMain(array<double, variantBitLength> &differenceTotal, int &countTotal, const set<array<unsigned char, 16>>&setPlainTexts, set<array<unsigned char, 16>>&setTotalKeys)//fix later.
{
    //set<array<unsigned char, 16>> setPlainTexts;
    set<array<unsigned char, 16>> setKeys;
    //genRandomSegmented(setPlainTexts, NUM_PLAINTEXTS / NUM_THREADS, 10);
    //genRandomSegmented(setKeys, NUM_KEYS / NUM_THREADS, 10);
    genRandomSegmented2(setKeys, NUM_KEYS / NUM_THREADS, NUM_SEGMENTS, setTotalKeys);

    AES aes;
    array<unsigned char, 16> state;
    array<array<double, 2>, 2> tMatrixControl;
    array<array<double, 2>, 2> tMatrixVariant;

    for (const auto &plainText : setPlainTexts)
    {
        for(const auto &key : setKeys)
        {
            state = plainText;
            aes.encrypt(state, key);//ciphertext now
            encodeText(state, plainText);
            Huffman huffman(state);
            Markov::generateMarkovTransitionMatrix(huffman.getHuffmanCodes(), tMatrixControl);
            
            //variant keys
            array<unsigned char, 16> stateVariant;
            array<unsigned char, 16> keyVariant;
            for(int i=0;i<variantBitLength;i++)
            {
                stateVariant=plainText;
                keyVariant = key;

                swapBits(keyVariant, variantBits[i]);
                aes.encrypt(stateVariant, keyVariant);//ciphertext now
                encodeText(stateVariant, plainText);
                Huffman huffmanVariant(stateVariant);

                Markov::generateMarkovTransitionMatrix(huffmanVariant.getHuffmanCodes(), tMatrixVariant);
                double difference;
                markovDifference(tMatrixControl, tMatrixVariant, difference);
                m.lock();
                differenceTotal[i] += difference;
                m.unlock();
            }
            m.lock(); 
            countTotal++;
            m.unlock();
        }
    }
}

int main()
{
    
    auto start = chrono::high_resolution_clock::now();

    set<array<unsigned char, 16>> setPlainTexts;
    genRandomSegmented(setPlainTexts, NUM_PLAINTEXTS, NUM_SEGMENTS);//generate plaintexts
    set<array<unsigned char, 16>> setTotalKeys;//create set to prevent duplication of keys between threads
    mutex m;
    array<double, variantBitLength> differenceTotal{};//for calculating avg difference of matrices
    array<double, variantBitLength> differenceAverage;
    int countTotal = 0;

    vector<thread> threads; 
    for(int i=0;i<NUM_THREADS;i++)//create threads
        threads.emplace_back(threadMain, ref(differenceTotal), ref(countTotal), ref(setPlainTexts), ref(setTotalKeys));//threads receive value instead of reference by default
    for(auto &th : threads)//wait for threads to finish
        th.join();
    for(int i=0;i<variantBitLength;i++)//calculate average difference of matrices
        differenceAverage[i] = differenceTotal[i] / countTotal;

    auto end = chrono::high_resolution_clock::now();

    chrono::duration<double> duration = end - start;
    cout << endl << duration.count() << endl;
    cout << countTotal << endl << endl;//total number of iterations (#plainTexts * #control keys)
    for(int i=0;i<variantBitLength;i++)
        cout << differenceAverage[i] << endl;//1 bit difference, 2 bit, 4, etc
    

   /*Not updated, move from 8 to variantBitLength
    set<array<unsigned char, 16>> setPlainTexts;
    set<array<unsigned char, 16>> setKeys;
    genRandomSegmented(setPlainTexts, 100, 10);//come back later to check for bugs.
    genRandomSegmented(setKeys, 1000, 10);

    AES aes;
    array<unsigned char, 16> state;
    array<array<double, 2>, 2> tMatrixControl;
    array<array<double, 2>, 2> tMatrixVariant;

    array<double, 8> differenceTotal{};
    array<double, 8> differenceAverage;
    int countTotal = NUM_KEYS * NUM_PLAINTEXTS;

    auto start = chrono::high_resolution_clock::now();

    for (const auto &plainText : setPlainTexts)
    {
        for(const auto &key : setKeys)
        {
            state = plainText;
            aes.encrypt(state, key);
            encodeText(state, plainText);
            Huffman huffman(state);
            Markov::generateMarkovTransitionMatrix(huffman.getHuffmanCodes(), tMatrixControl);
            
            //variant keys
            array<unsigned char, 16> stateVariant;
            array<unsigned char, 16> keyVariant;
            for(int i=0;i<8;i++)
            {
                stateVariant=plainText;
                keyVariant = key;

                swapBits(keyVariant, pow(2,i));
                aes.encrypt(stateVariant, keyVariant);
                encodeText(stateVariant, plainText);
                Huffman huffmanVariant(stateVariant);

                Markov::generateMarkovTransitionMatrix(huffmanVariant.getHuffmanCodes(), tMatrixVariant);
                double difference;
                markovDifference(tMatrixControl, tMatrixVariant, difference);
                differenceTotal[i] += difference;
            }
        }
    }
    
    for(int i=0;i<8;i++)
    {
        differenceAverage[i] = differenceTotal[i] / countTotal;
        cout << differenceAverage[i] << endl;
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cout << endl << duration.count();
    */

    return 0;
}

void encodeText(array<unsigned char, 16> &state, const array<unsigned char, 16> &plainText)
{
    for(int i=0;i<16;i++) 
        state[i] ^= plainText[i];
}

void markovDifference(const array<array<double, 2>, 2>&mControl, const array<array<double, 2>, 2>&mVariant, double &difference)
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
    difference = sqrt(total);
}

void swapBits(array<unsigned char, 16>&key, const int &num)
{
    if(num != 128)//1 to 64 bits flipped
    {
        set<int> indices;//makes sure no duplicates of flipping
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

void genRandomSegmented(set<array<unsigned char, 16>> &charSet, int size, int segments)
{
    random_device seed;//seed for random number generator
    mt19937_64 gen(seed());//random number generator
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

void genRandomSegmented2(set<array<unsigned char, 16>> &charSet, int size, int segments, set<array<unsigned char, 16>> &totalSet)//for use with keys only in threads
{
    random_device seed;//seed for random number generator
    mt19937_64 gen(seed());//random number generator
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
        m.lock();
        bool added = totalSet.insert(temp).second;//prevents advancing to the next segment in case of duplicate in total set
        m.unlock();
        if(added)
        {
            charSet.insert(temp);//add to local set
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