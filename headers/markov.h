#ifndef MARKOV_H
#define MARKOV_H
#include <array>
#include <vector>

class Markov{
    public:
        //generate 2d transition matrix
        static void generateMarkovTransitionMatrix(const std::array<std::vector<bool>, 16>& , std::array<std::array<double, 2>, 2>&);

};

#endif