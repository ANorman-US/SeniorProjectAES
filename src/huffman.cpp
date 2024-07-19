#include "../headers./huffman.h"

Huffman::Huffman(const std::array<unsigned char, 16> &array)
{

}

Huffman::~Huffman()
{

}

std::map<unsigned char, std::vector<bool>> Huffman::getHuffmanCodes()
{
    return codes;
}