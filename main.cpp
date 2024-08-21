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
#include "./headers/crypto.h"
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
const int NUM_KEYS = 10'0;
const int NUM_SEGMENTS = 10;
const int NUM_THREADS = 10;
const __uint128_t UINT128_MAX = ~__uint128_t{};

//# of bits being altered in variant keys
const int variantBitLength = 14;
const array<int, variantBitLength> variantBits = {1,2,4,8,16,32,64,96,112,120,124,126,127,128};

mutex m, m1, m2;

void threadMain(array<double, variantBitLength> &differenceTotal, int &countTotal, const set<array<unsigned char, 16>>&setPlainTexts, set<array<unsigned char, 16>>&setTotalKeys)//fix later.
{
    //set<array<unsigned char, 16>> setPlainTexts;
    set<array<unsigned char, 16>> setKeys;
    //genRandomSegmented(setPlainTexts, NUM_PLAINTEXTS / NUM_THREADS, 10);
    //genRandomSegmented(setKeys, NUM_KEYS / NUM_THREADS, 10);
    Crypto::genRandomSegmented(setKeys, NUM_KEYS / NUM_THREADS, NUM_SEGMENTS, setTotalKeys, m2);

    AES aes;
    array<unsigned char, 16> state;
    array<array<double, 2>, 2> tMatrixControl;
    array<array<double, 2>, 2> tMatrixVariant;
    array<double, variantBitLength> differenceTotalTemp;
    int countTotalLocal = 0;

    for (const auto &plainText : setPlainTexts)
    {
        for(const auto &key : setKeys)
        {
            state = plainText;
            aes.encrypt(state, key);//ciphertext now
            Crypto::encodeText(state, plainText);
            Huffman huffman(state);
            Markov::generateMarkovTransitionMatrix(huffman.getHuffmanCodes(), tMatrixControl);
            
            //variant keys
            array<unsigned char, 16> stateVariant;
            array<unsigned char, 16> keyVariant;
            for(int i=0;i<variantBitLength;i++)
            {
                stateVariant=plainText;
                keyVariant = key;

                Crypto::swapBits(keyVariant, variantBits[i]);
                aes.encrypt(stateVariant, keyVariant);//ciphertext now
                Crypto::encodeText(stateVariant, plainText);
                Huffman huffmanVariant(stateVariant);

                Markov::generateMarkovTransitionMatrix(huffmanVariant.getHuffmanCodes(), tMatrixVariant);
                double difference;
                Crypto::markovDifference(tMatrixControl, tMatrixVariant, difference);
                differenceTotalTemp[i] += difference;
            }
            countTotalLocal++;
        }
    }
    
    m1.lock();
    countTotal+=countTotalLocal;
    m1.unlock();
    for(int i=0;i<variantBitLength;i++)
    {
        m.lock();
        differenceTotal[i]+=differenceTotalTemp[i];
        m.unlock();
    }
}

int main()
{
    
    auto start = chrono::high_resolution_clock::now();

    set<array<unsigned char, 16>> setPlainTexts;
    Crypto::genRandomSegmented(setPlainTexts, NUM_PLAINTEXTS, NUM_SEGMENTS);//generate plaintexts
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