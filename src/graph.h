#include <iostream>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <vector>
#include <string>
#include <map>

using namespace std;


class BasicBlock {
private:
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
    }

    long long getOffset() const { return offset_; }
    long long getJumpOff() const { return jump_off_; }
    long long getFailOff() const { return fail_off_; }
    BasicBlock* getFather() { return father_; }
    BasicBlock* getJump() { return jump_; }
    BasicBlock* getFail() { return fail_; }

    void setJump(BasicBlock* jump) { jump_ = jump; }
    void setFail(BasicBlock* fail) { fail_ = fail; }
    void setFather(BasicBlock* father) { father_ = father; }
};

class Function {
private:
    long long id_;
    string name_;
    vector<BasicBlock*> bb_list_;
    BasicBlock* root_;
    vector<long long> callees_;
    vector<Function*> childs_;

public:
    Function() {}
    Function(long long id, string& name, vector<long long> callees) {
        id_ = id;
        name_ = name;
        callees_ = callees;
    }

    string& getName() { return name_; }
    long long& getID() { return id_; }
    vector<BasicBlock*>& getBBList() { return bb_list_; }
    BasicBlock* getRoot() { return root_; }
    vector<long long>& getCallees() { return callees_; }
    vector<Function*>& getChilds() { return childs_; }

    void setName(string& name) { name_ = name; }
    void setID(long long id) { id_ = id; }
    void setRoot(BasicBlock* bb) { root_ = bb;}
    void addChild(Function* func) { childs_.push_back(func); }
    void addBB(BasicBlock* bb) { bb_list_.push_back(bb); }

    void genContronFlowGraph();
};

class CallGraph {
private:
    vector<Function*> func_list_;
    Function* root_;
public:
    vector<Function*>& getFuncList() { return func_list_; }
    Function* getRoot() { return root_; }

    void setRoot(Function* func) { root_ = func;}
    void addFunc(Function* func) { func_list_.push_back(func); }
    void genCallGraph();
};
