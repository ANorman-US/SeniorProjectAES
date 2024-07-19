//Alexander Norman
//AES Codebreaking with Huffman Coding
#include "./headers/aes.h"
#include "./headers/huffman.h"
#include <iostream>
#include <array>
#include <set>
#include <chrono>

using namespace std;

const int NUM_PLAINTEXTS = 100'000;
const int NUM_KEYS = 1'000'000;

void encodeText(array<unsigned char, 16>&, const array<unsigned char, 16>&);//plainText XOR cipherText 
void genRandom16(set<array<unsigned char, 16>>&, int);//set, size. Generates random 16byte unsigned char arrays and adds to set

int main()
{
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

    encodeText(state, plainText);

    //Huffman test
    Huffman huffman(plainText);
    
    auto start = chrono::high_resolution_clock::now();

    set<array<unsigned char, 16>> setPlainTexts;
    set<array<unsigned char, 16>> setKeys;
    genRandom16(setPlainTexts, NUM_PLAINTEXTS);
    genRandom16(setKeys, NUM_KEYS);

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

void genRandom16(set<array<unsigned char, 16>> &charSet, int size)
{
    array<unsigned char, 16> temp;
    while(charSet.size() < size)
    {
        for(int i=0;i<temp.size();i++)
            temp[i] = rand()%256;//generate 0-255
        charSet.insert(temp);
    }
}