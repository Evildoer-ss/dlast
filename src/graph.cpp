#include "graph.h"

void Function::genContronFlowGraph() {
    for (int i = 0; i < bb_list_.size(); ++i) {
        BasicBlock* cur_bb = bb_list_[i];
        if (cur_bb->getFailOff() != -1) {
            for (int j = 0; j < bb_list_.size(); ++j) {
                if (bb_list_[j]->getOffset() == cur_bb->getFailOff()) {
                    cur_bb->setFail(bb_list_[j]);
                    bb_list_[j]->setFather(cur_bb);
                    break;
                }
            }
        }
        if (cur_bb->getJumpOff() != -1) {
            for (int j = 0; j < bb_list_.size(); ++j) {
                if (bb_list_[j]->getOffset() == cur_bb->getJumpOff()) {
                    cur_bb->setJump(bb_list_[j]);
                    bb_list_[j]->setFather(cur_bb);
                    break;
                }
            }
        }
    }
    for (int i = 0; i < bb_list_.size(); ++i) {
        if (bb_list_[i]->getFather() == nullptr) {
            root_ = bb_list_[i];
            break;
        }
    }
    return;
}

// may mutator's location
string vector2str(vector<string>& str) {
    string res = "";
    for (int i = 0; i < str.size(); ++i) {
        res += str[i];
    }
    return res;
}

void Function::dfs(vector<BasicBlock*>& prevs, BasicBlock* cur) {
    if (cur->isTag()) { return; }
    cur->Tag();
    prevs.push_back(cur);
    if (cur->getJump() == nullptr && cur->getFail() == nullptr) {
        for (int i = 0; i < prevs.size(); ++i) {
            BasicBlock* cur = prevs[i];
            string str = vector2str(cur->getRefs());
            if (find(corpus_.begin(), corpus_.end(), str) == corpus_.end()) {
                corpus_.push_back(str);
            }
        }
        prevs.pop_back();
        cur->UnTag();
        return;
    }
    if (cur->getFail()) { dfs(prevs, cur->getFail()); }
    if (cur->getJump()) { dfs(prevs, cur->getJump()); }
    prevs.pop_back();
    cur->UnTag();
    return;
}

void Function::genCorpus() {
    vector<BasicBlock*> prevs;
    if (root_ == nullptr) { return; }
    dfs(prevs, root_);
    return;
}

void CallGraph::genCallGraph() {
    for (int i = 0; i < func_list_.size(); ++i) {
        Function* cur_func = func_list_[i];
        cur_func->genContronFlowGraph();
        for (int j = 0; j < cur_func->getCallees().size(); ++j) {
            long long callee_id = cur_func->getCallees()[j];
            Function* cur_child = nullptr;
            for (int k = 0; k < func_list_.size(); ++k) {
                if (callee_id == func_list_[k]->getID()) {
                    cur_child = func_list_[k];
                    break;
                }
            }
            if (cur_child == nullptr) { continue; }
            cur_func->addChild(cur_child);
        }
    }

    // find root function node
    for (int i = 0; i < func_list_.size(); ++i) {
        if (func_list_[i]->getFather() == nullptr) {
            addRoot(func_list_[i]);
        }
    }
    return;
}

void CallGraph::sub_dfs(vector<Function*> prevs, vector<int>& sub_prevs, int idx) {
    if (sub_prevs.size() == prevs.size()) {
        string str = "";
        // may mutator?
        for (int i = 0; i < prevs.size(); ++i) {
            if (sub_prevs[i] == -1) { continue; }
            str += prevs[i]->getCorpus()[sub_prevs[i]];
        }
        if (str.compare("") && find(corpus_.begin(), corpus_.end(), str) == corpus_.end()) {
            corpus_.push_back(str);
        }
        return;
    }

    if (prevs[idx]->getCorpus().size() == 0) {
        sub_prevs.push_back(-1);
        sub_dfs(prevs, sub_prevs, idx + 1);
        sub_prevs.pop_back();
        return;
    }

    for (int i = 0; i < prevs[idx]->getCorpus().size(); ++i) {
        sub_prevs.push_back(i);
        sub_dfs(prevs, sub_prevs, idx + 1);
        sub_prevs.pop_back();
    }
    return;
}

void CallGraph::dfs(vector<Function*>& prevs, Function* cur) {
    if (cur->isTag()) { return; }
    prevs.push_back(cur);
    cur->Tag();
    if (cur->getChilds().size() == 0) {
        unsigned long long times = 1;
        for (int i = 0; i < prevs.size(); ++i) {
            Function* cur = prevs[i];
            if (!cur->isGened()) { cur->genCorpus(); }
            auto sz = cur->getCorpus().size();
            if (sz) { times *= sz; }
        }
        if (times < MAX_RECU_TIMES) {
            vector<int> sub_prevs;
            if (prevs.size() != 0) { sub_dfs(prevs, sub_prevs, 0); }
        }
        else {
            // cout << "WARNING: " << times << " may too big for recursion." << endl;
        }
        
        // for (int i = 0; i < prevs.size(); ++i) {
        //     Function* cur = prevs[i];
        //     // if (!cur->isGened()) { cur->genCorpus(); }
        //     // auto sz = cur->getCorpus().size();
        //     if (cur->getCorpus().size() && cur->getCorpus()[0].compare("")) {
        //         cout << cur->getCorpus()[0] << endl;
        //     }
        //     // TODO
        //     string str = vector2str(cur->getCorpus());
        //     if (str.compare("")) { corpus_.push_back(str); }
        // }
        prevs.pop_back();
        cur->UnTag();
        return;
    }
    for (int i = 0; i < cur->getChilds().size(); ++i) {
        dfs(prevs, cur->getChilds()[i]);
    }
    prevs.pop_back();
    cur->UnTag();
    return;
}

void CallGraph::genCorpus(ofstream& out) {
    vector<Function*> prevs;
    for (int i = 0; i < root_list_.size(); ++i) {
        Function* root = root_list_[i];
        prevs.clear();
        dfs(prevs, root);
    }

    for (auto it : corpus_) { out << it << endl; }

    return;
}
