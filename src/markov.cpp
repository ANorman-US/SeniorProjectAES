#include "../headers./markov.h"

void Markov::generateMarkovTransitionMatrix(const std::array<std::vector<bool>, 16>& codewords, std::array<std::array<double, 2>, 2>& tMatrix) 
{
    int zero_to_zero = 0;
    int zero_to_one = 0;
    int one_to_zero = 0;
    int one_to_one = 0;

    for(const auto &codeword : codewords)
    {
        for(int i=0;i<codeword.size()-1;i++)
        {
            if(codeword[i]==0)
            {
                if(codeword[i+1]==0)
                    zero_to_zero++;
                else
                    zero_to_one++;
            }
            else
            {
                if(codeword[i+1]==0)
                    one_to_zero++;
                else
                    one_to_one++;
            }
        }
    }

    double p_zero_to_zero = zero_to_zero / (double)(zero_to_one+zero_to_zero);
    double p_zero_to_one = zero_to_one / (double)(zero_to_one+zero_to_zero);
    double p_one_to_zero = one_to_zero / (double)(one_to_one+one_to_zero);
    double p_one_to_one = one_to_one / (double)(one_to_one+one_to_zero);

    tMatrix[0][0] = p_zero_to_zero;
    tMatrix[0][1] = p_zero_to_one;
    tMatrix[1][0] = p_one_to_zero;
    tMatrix[1][1] = p_one_to_one;
}
