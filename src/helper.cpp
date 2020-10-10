#include "graph.h"
#include "json.hpp"
#include "helper.h"

#include <fstream>

using namespace std;
using json = nlohmann::json;

CallGraph* InitFromJson(string tmp_dir) {
    string cfg_path = tmp_dir + "/cfg_fixed.json";
    string cg_path = tmp_dir + "/cg_fixed.json";

    cout << "control flow graph path: " << cfg_path << endl;
    cout << "call graph path: " << cg_path << endl;

    ifstream in_cfg(cfg_path);
    json raw_cfg;
    in_cfg >> raw_cfg;

    ifstream in_cg(cg_path);
    json raw_cg;
    in_cg >> raw_cg;

    CallGraph* call_graph = new CallGraph();

    for (auto i = 0; i < raw_cg.size(); ++i) {
        json cur_func_raw = raw_cg[i];
        long long cur_id = cur_func_raw["id"];
        string cur_name = cur_func_raw["name"];
        vector<long long> cur_callees = cur_func_raw["callee"];
        Function* cur_func = new Function(cur_id, cur_name, cur_callees);
        for (int j = 0; j < raw_cfg[to_string(cur_id)]["blocks"].size(); ++j) {
            json cur_bb_raw = raw_cfg[to_string(cur_id)]["blocks"][j];
            long long cur_offset = cur_bb_raw["offset"];
            long long cur_jump = cur_bb_raw["jump"];
            long long cur_fail = cur_bb_raw["fail"];
            vector<string> cur_refs = cur_bb_raw["refs"];
            BasicBlock* cur_bb = new BasicBlock(cur_offset, cur_refs, cur_jump, cur_fail);
            cur_func->addBB(cur_bb);
        }
        call_graph->addFunc(cur_func);
    }
    return call_graph;
}

CallGraph* GenerateCallGraph(string tmp_dir) {
    CallGraph* call_graph = InitFromJson(tmp_dir);
    call_graph->genCallGraph();

    return call_graph;
}

extern "C" {

void GenerateCorpus(char* c_tmp_dir) {
    string tmp_dir = string(c_tmp_dir);

    CallGraph* call_graph = GenerateCallGraph(tmp_dir);

    call_graph->genCorpus();
    call_graph->PrintCorpus();

    return;
}

}
