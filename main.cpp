//Alexander Norman
//AES Codebreaking with Huffman Coding
#include "./headers/aes.h"
#include <iostream>
#include <string>

using namespace std;

void encodeText(unsigned char*, const unsigned char*);

int main()
{
    AES aes;

    unsigned char plainText[16] = {0x19, 0xA0, 0x9A, 0xE9,
                                   0x3D, 0xF4, 0xC6, 0xF8,
                                   0xE3, 0xE2, 0x8D, 0x48,
                                   0xBE, 0x2B, 0x2A, 0x08};
    
    unsigned char key[16] = {0xA0, 0x88, 0x23, 0x2A,
                             0xFA, 0x54, 0xA3, 0x6C,
                             0xFE, 0x2C, 0x39, 0x76,
                             0x17, 0xB1, 0x39, 0x05};                                    
    unsigned char state[16];
    memcpy(state, plainText, 16);



    aes.encrypt(state, key);
    encodeText(state, plainText);

    

    return 0;
}

void encodeText(unsigned char* state, const unsigned char* plainText)
{
    for(int i=0;i<16;i++)
        state[i] ^= plainText[i];
}