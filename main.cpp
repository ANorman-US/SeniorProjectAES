//Alexander Norman
//AES Codebreaking with Huffman Coding
#include "./headers/aes.h"
#include "./headers/huffman.h"
#include <iostream>
#include <array>
#include <unordered_set>
#include <chrono>

using namespace std;

//hash function for array for usage in unordered_set
//Code adapted from https://stackoverflow.com/questions/8026890/c-how-to-insert-array-into-hash-set
namespace std {
    template<typename T, size_t N>
    struct hash<array<T, N>> {
        typedef array<T, N> argument_type;
        typedef size_t result_type;

        result_type operator()(const argument_type& a) const {
            hash<T> hasher;
            result_type h = 0;
            for (result_type i = 0; i < N; i++) {
                h = h * 31 + hasher(a[i]);
            }
            return h;
        }
    };
}


const int NUM_PLAINTEXTS = 100'000;
const int NUM_KEYS = 1'000'000;

void encodeText(array<unsigned char, 16>&, const array<unsigned char, 16>&);//plainText XOR cipherText 
void genRandom16(unordered_set<array<unsigned char, 16>>&, int);//set, size. Generates random 16byte unsigned char arrays and adds to set

int main()
{
    //Testing Purposes
    /*array<unsigned char, 16> plainText = {0x19, 0xA0, 0x9A, 0xE9,
                                          0x3D, 0xF4, 0xC6, 0xF8,
                                          0xE3, 0xE2, 0x8D, 0x48,
                                          0xBE, 0x2B, 0x2A, 0x08};    
    array<unsigned char, 16> key = {0xA0, 0x88, 0x23, 0x2A,
                                    0xFA, 0x54, 0xA3, 0x6C,
                                    0xFE, 0x2C, 0x39, 0x76,
                                    0x17, 0xB1, 0x39, 0x05};                                    
    array<unsigned char, 16> state;
    state = plainText;

    AES aes;
    aes.encrypt(state, key);
    encodeText(state, plainText);*/

    AES aes;
    Huffman huffman;
    
    //auto start = chrono::high_resolution_clock::now();
    /*auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cout << endl << duration.count();*/

    unordered_set<array<unsigned char, 16>> setPlainTexts;
    unordered_set<array<unsigned char, 16>> setKeys;
    genRandom16(setPlainTexts, NUM_PLAINTEXTS);
    genRandom16(setKeys, NUM_KEYS);

     return 0;
}

void encodeText(array<unsigned char, 16> &state, const array<unsigned char, 16> &plainText)
{
    for(int i=0;i<16;i++)
        state[i] ^= plainText[i];
}

void genRandom16(unordered_set<array<unsigned char, 16>> &charSet, int size)
{
    array<unsigned char, 16> temp;
    while(charSet.size() < size)
    {
        for(int i=0;i<temp.size();i++)
            temp[i] = rand()%256;//generate 0-255
        charSet.insert(temp);
    }
}