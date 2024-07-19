#include "../headers./huffman.h"

Huffman::Huffman(const std::array<unsigned char, 16> &array)
{
    generateTree(array);
    std::vector<bool> hCodes;
    generateCodes(root, hCodes);
}

Huffman::~Huffman()
{

}

void Huffman::generateTree(const std::array<unsigned char, 16> &array)
{
    std::map<unsigned char, int> frequency;
    for(int i=0;i<16;i++)//map with 0s
        frequency[i] = 0;
    
    for(int i=0;i<16;i++)//count frequencies to map.
    {
        unsigned char high = (array[i] >> 4) & 0x0F;
        unsigned char low = array[i] & 0x0F;

        frequency[high]++;
        frequency[low]++;
    }

    std::priority_queue<HuffmanNode*, std::vector<HuffmanNode*>, CompareHuffmanNode> pq;//minheap
    for(auto it : frequency)//push to prioQ
    {
        HuffmanNode* h = new HuffmanNode(it.first, it.second);
        pq.push(h);
    }

    while(pq.size() > 1)
    {
        HuffmanNode* left = pq.top(); pq.pop();
        HuffmanNode* right = pq.top(); pq.pop();

        HuffmanNode *pair = new HuffmanNode('\0' , left->freq+right->freq);
        pair->left=left;
        pair->right=right;
        pq.push(pair);
    }
    root = pq.top();
    pq.pop();
}

void Huffman::generateCodes(HuffmanNode *node, std::vector<bool> code)
{
    if(!node)
        return;
    
    if(node->right == nullptr && node->left == nullptr)
        codes[node->c] = code;
    
    std::vector<bool> leftC= code; leftC.push_back(0);
    std::vector<bool> rightC= code; rightC.push_back(1);
    generateCodes(node->left, leftC);
    generateCodes(node->right, rightC);
}

std::map<unsigned char, std::vector<bool>> Huffman::getHuffmanCodes()
{
    return codes;
}