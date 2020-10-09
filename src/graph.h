#include <iostream>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <vector>
#include <string>

using namespace std;


class BasicBlock {
private:
    long long offset_;
    vector<string> refs_;
    BasicBlock* jump_;
    BasicBlock* fail_;

public:
    BasicBlock() {}
    BasicBlock(long long offset, vector<string> refs) {
        offset_ = offset;
        refs_ = refs;
        jump_ = nullptr;
        fail_ = nullptr;
    }
};

class Function {
private:

public:

};

class CallGraph {
private:

public:

};
