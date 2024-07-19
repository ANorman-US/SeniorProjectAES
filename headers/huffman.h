#ifndef HUFFMAN_H
#define HUFFMAN_H
#include <vector>
#include <array>
#include <map>

class Huffman{
    private:
        struct HuffmanNode{
            char c;
            int freq;
            HuffmanNode* left;
            HuffmanNode* right;
            HuffmanNode(char ch, int f) {c = ch; freq = f; left = nullptr; right = nullptr;};
            //for priority queue
            bool operator>(const HuffmanNode &other) const{
                return freq > other.freq;
            }
        };
        HuffmanNode* root;
        std::map<unsigned char, std::vector<bool>> codes;

    public:
        Huffman(const std::array<unsigned char, 16>&);//makes tree and codes
        ~Huffman();//deconstructor to clean up tree
        std::map<unsigned char, std::vector<bool>> getHuffmanCodes();//returns codes
            
};

#endif