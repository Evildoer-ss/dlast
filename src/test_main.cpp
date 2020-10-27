#include "helper.h"
#include <cstring>
#include <iostream>
#include <ctime>

int main() {
    std::time_t start = std::time(0);
    char* path = strdup("/Users/ssj/tmp/1603424154.706423");
    GenerateCorpus(path);
    std::cout << "time: " << std::time(0) - start << std::endl;
    return 0;
}
