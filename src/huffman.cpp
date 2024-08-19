#include "../headers/huffman.h"

Huffman::Huffman(const std::array<unsigned char, 16> &array)
{
    generateTree(array);
    std::vector<bool> hCodes;
    generateCodes(root, hCodes);
}

Huffman::~Huffman()
{
    delete root;
}

void Huffman::generateTree(const std::array<unsigned char, 16> &array)
{
    std::array<unsigned char, 16> frequency;
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
    for(int i=0;i<16;i++)
    {
        HuffmanNode* h = new HuffmanNode(i, frequency[i]);
        pq.push(h);
    }

    while(pq.size() > 1)
    {
        HuffmanNode* left = pq.top(); pq.pop();
        HuffmanNode* right = pq.top(); pq.pop();

        HuffmanNode *pair = new HuffmanNode(-1 , left->freq+right->freq);//non-leaf node
        pair->left=left;
        pair->right=right;
        pq.push(pair);
    }
    root = pq.top();
    pq.pop();
}

void Huffman::generateCodes(HuffmanNode *node, std::vector<bool> &code)
{
    if(!node)
        return;
    
    if(node->c != -1)//-1 indicates non-leaf node
        codes[node->c] = code;
    
    code.push_back(0);
    generateCodes(node->left, code);
    code.pop_back();

    code.push_back(1);
    generateCodes(node->right, code);
    code.pop_back();
}

void Huffman::deleteTree(HuffmanNode *node)
{
    if(!node)
        return;
    deleteTree(node->left);
    deleteTree(node->right);
    delete node;
}

std::array<std::vector<bool>, 16> Huffman::getHuffmanCodes()
{
    return codes;
}