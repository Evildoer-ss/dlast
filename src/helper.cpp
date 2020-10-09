#include "graph.h"
#include "json.hpp"
#include "helper.h"

#include <fstream>

using namespace std;
using json = nlohmann::json;

void InitBasicBlocks(string cfg_path) {
    ifstream in(cfg_path);
    string raw_cfg;
    in >> raw_cfg;
    auto cfg_json = json::parse(raw_cfg);
    
}

void InitFunctions(string cg_path) {

}

CallGraph* GenerateCallGraph(string tmp_dir) {
    InitBasicBlocks(tmp_dir + "/cfg_fixed.json");
    InitFunctions(tmp_dir + "/cg_fixed.json");


    return;
}

extern "C" {

void GenerateCorpus(char* c_tmp_dir) {
    string tmp_dir = string(c_tmp_dir);

    CallGraph* call_graph = GenerateCallGraph(tmp_dir);



    return;
}

}
