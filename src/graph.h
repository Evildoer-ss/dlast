#include <iostream>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <vector>
#include <string>
#include <fstream>

#define MAX_RECU_TIMES 100000

using namespace std;


class BasicBlock {
private:
    bool is_tag_ = false;
    long long offset_, jump_off_, fail_off_;
    vector<string> refs_;
    BasicBlock* jump_;
    BasicBlock* fail_;
    BasicBlock* father_;

public:
    BasicBlock() {}
    BasicBlock(long long offset, vector<string> refs, long long jump, long long fail) {
        offset_ = offset;
        refs_ = refs;
        jump_off_ = jump;
        fail_off_ = fail;
        jump_ = nullptr;
        fail_ = nullptr;
        father_ = nullptr;
        is_tag_ = false;
    }

    void Tag() { is_tag_ = true; }
    void UnTag() { is_tag_ = false; }
    bool isTag() { return is_tag_; }

    long long getOffset() const { return offset_; }
    long long getJumpOff() const { return jump_off_; }
    long long getFailOff() const { return fail_off_; }
    BasicBlock* getFather() { return father_; }
    BasicBlock* getJump() { return jump_; }
    BasicBlock* getFail() { return fail_; }
    vector<string>& getRefs() { return refs_; }

    void setJump(BasicBlock* jump) { jump_ = jump; }
    void setFail(BasicBlock* fail) { fail_ = fail; }
    void setFather(BasicBlock* father) { father_ = father; }
};

class Function {
private:
    bool is_tag_ = false, is_gened_ = false;
    long long id_;
    string name_;
    vector<BasicBlock*> bb_list_;
    BasicBlock* root_ = nullptr;
    vector<long long> callees_;
    Function* father_ = nullptr;
    vector<Function*> childs_;
    vector<string> corpus_;

public:
    Function() {}
    Function(long long id, string& name, vector<long long> callees) {
        id_ = id;
        name_ = name;
        callees_ = callees;
    }

    void Tag() { is_tag_ = true; }
    void UnTag() { is_tag_ = false; }
    bool isTag() { return is_tag_; }

    bool isGened() { return is_gened_; }

    string& getName() { return name_; }
    long long& getID() { return id_; }
    vector<BasicBlock*>& getBBList() { return bb_list_; }
    BasicBlock* getRoot() { return root_; }
    vector<long long>& getCallees() { return callees_; }
    Function* getFather() { return father_; }
    vector<Function*>& getChilds() { return childs_; }
    vector<string>& getCorpus() { return corpus_; }

    void setName(string& name) { name_ = name; }
    void setID(long long id) { id_ = id; }
    void setRoot(BasicBlock* bb) { root_ = bb;}
    void setFather(Function* fa) { father_ = fa;}
    void addChild(Function* func) { childs_.push_back(func); }
    void addBB(BasicBlock* bb) { bb_list_.push_back(bb); }

    void genContronFlowGraph();

    void dfs(vector<BasicBlock*>&, BasicBlock*);
    void genCorpus();
};

class CallGraph {
private:
    vector<Function*> func_list_;
    vector<Function*> root_list_;
    vector<string> corpus_;

public:
    vector<Function*>& getFuncList() { return func_list_; }
    vector<Function*>& getRootList() { return root_list_; }
    vector<string>& getCorpus() { return corpus_; }

    void addRoot(Function* func) { root_list_.push_back(func); }
    void addFunc(Function* func) { func_list_.push_back(func); }
    void genCallGraph();

    void sub_dfs(vector<Function*>, vector<int>&, int);
    void dfs(vector<Function*>&, Function*);
    void genCorpus(ofstream& out);

    void PrintCorpus() const {
        for (auto it : corpus_) {
            cout << it << std::endl;
        }
        return;
    }
};
