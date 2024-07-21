#ifndef HUFFMAN_H
#define HUFFMAN_H
#include <vector>
#include <array>
#include <queue>

class Huffman{
    private:
        struct HuffmanNode{
            signed char c;
            int freq;
            HuffmanNode* left;
            HuffmanNode* right;
            HuffmanNode(char ch, int f) {c = ch; freq = f; left = nullptr; right = nullptr;};
            ~HuffmanNode()
            {
                delete left;
                delete right;
            }
        };
        //custom comparator for priority queue
        struct CompareHuffmanNode{
            bool operator()(HuffmanNode* one, HuffmanNode* two){
                if(one->freq == two->freq)//alphabetical tiebreaking for consistency. non-leaf nodes (-1)go to the left of leaf nodes
                    return one->c > two->c;
                return one->freq > two->freq;
            }
        };

        HuffmanNode* root;
        std::array<std::vector<bool>, 16> codes;

        void generateTree(const std::array<unsigned char, 16>&);
        void generateCodes(HuffmanNode*, std::vector<bool>&);
        void deleteTree(HuffmanNode*);

    public:
        Huffman(const std::array<unsigned char, 16>&);//generates tree and codes
        ~Huffman();//deconstructor to clean up tree
        std::array<std::vector<bool>, 16> getHuffmanCodes();//returns codes
            
};

#endif