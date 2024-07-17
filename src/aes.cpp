#include "../headers./aes.h"

void AES::subBytes(std::array<unsigned char, 16> &state)
{
    for(int i=0;i<16;i++)
        state[i]=sTable[state[i]];
}

void AES::shiftRows(std::array<unsigned char, 16> &state)
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

unsigned char AES::galoisMult(unsigned char byte, int num)
{
    unsigned char result = byte;
    //mult by 2
    result = result << 1;
    if(byte >= 128)
        result = result ^ 0x1B;
    //mult by 3
    if(num == 3)
        result = result ^ byte;
    return result;
}

void AES::mixColumns(std::array<unsigned char, 16> &state)
{
    /*Galois field
    02 03 01 01
    01 02 03 01
    01 01 02 03
    03 01 01 02*/
    std::array<unsigned char, 16> temp;
    for(int i=0;i<4;i++)
    {
        temp[i] = galoisMult(state[i], 2) ^ galoisMult(state[i+4], 3) ^ state[i+8] ^ state[i+12];
        temp[i+4] = state[i] ^ galoisMult(state[i+4], 2) ^ galoisMult(state[i+8], 3) ^ state[i+12];
        temp[i+8] = state[i] ^ state[i+4] ^ galoisMult(state[i+8], 2) ^ galoisMult(state[i+12], 3);
        temp[i+12] = galoisMult(state[i], 3) ^ state[i+4] ^ state[i+8] ^ galoisMult(state[i+12], 2);
    }
    state=temp;
}

void AES::addKey(std::array<unsigned char, 16> &state, const std::array<unsigned char, 16> &key)
{
    for(int i=0;i<16;i++)
        state[i]^=key[i];
}

void AES::encrypt(std::array<unsigned char, 16> &state, const std::array<unsigned char, 16> &key)
{
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addKey(state, key);
}

