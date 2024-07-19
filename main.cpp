//Alexander Norman
//AES Crpytanalysis
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