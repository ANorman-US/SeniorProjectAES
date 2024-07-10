#include "../headers./aes.h"

void AES::subBytes(unsigned char* state)
{
    for(int i=0;i<16;i++)
        state[i]=sTable[state[i]];
}

void AES::shiftRows(unsigned char* state)
{
    unsigned char temp;
    //second row shift left once
    temp = state[4];
    state[4]=state[5];
    state[5]=state[6];
    state[6]=state[7];
    state[7] = temp;
    //third row shift left twice
    temp = state[8];
    state[8]=state[10];
    state[10]=temp;
    temp = state[9];
    state[9]=state[11];
    state[11]= temp;
    //fourth row shift right once
    temp = state[15];
    state[15]=state[14];
    state[14]=state[13];
    state[13]=state[12];
    state[12]=temp;
}

void AES::mixColumns(unsigned char* state)
{

}

void AES::encrypt(unsigned char* state, const unsigned char *plainText, const unsigned char *key)
{
    subBytes(state);
    shiftRows(state);
}

