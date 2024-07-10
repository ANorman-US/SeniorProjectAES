//Alexander Norman
//AES Codebreaking with Huffman Coding
#include "./headers/aes.h"
#include <iostream>
#include <string>

using namespace std;

int main()
{
    AES aes;
    unsigned char plainText[16] = {'h','e','l','l','o',' ','w','o','r','l','d',' ','t','e','s','t'};
    unsigned char state[16];
    unsigned char key[16] = {'t','e','s','t','i','n','g',' ','t','h','i','s',' ','k','e','y'};
    memcpy(state, plainText, 16);
    aes.encrypt(state, plainText, key);
    for(int i=0;i<16;i++)
        cout << state[i];
    

    return 0;
}