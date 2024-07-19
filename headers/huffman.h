#ifndef HUFFMAN_H
#define HUFFMAN_H
#include <vector>
#include <array>
#include <map>
#include <queue>

class Huffman{
    private:
        struct HuffmanNode{
            char c;
            int freq;
            HuffmanNode* left;
            HuffmanNode* right;
            HuffmanNode(char ch, int f) {c = ch; freq = f; left = nullptr; right = nullptr;};
        };
        //custom comparator for priority queue
        struct CompareHuffmanNode{
            bool operator()(HuffmanNode* one, HuffmanNode* two){
                if(one->freq == two->freq)//alphabetical tiebreaking for consistency
                    return one->c > two->c;
                return one->freq > two->freq;
            }
        };

        HuffmanNode* root;
        std::map<unsigned char, std::vector<bool>> codes;

        void generateTree(const std::array<unsigned char, 16>&);
        void generateCodes(HuffmanNode*, std::vector<bool>);

    public:
        Huffman(const std::array<unsigned char, 16>&);//makes tree and codes
        ~Huffman();//deconstructor to clean up tree
        std::map<unsigned char, std::vector<bool>> getHuffmanCodes();//returns codes
            
};

#endif