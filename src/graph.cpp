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
            corpus_.push_back(vector2str(cur->getRefs()));
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
        // if (!func_list_[i]->getName().compare("method.AppDelegate.application:openURL:options:")) {
        if (!func_list_[i]->getName().compare("method.GXDataManager.saveGXDefaultClientId:")) {
            root_ = func_list_[i];
            break;
        }
    }
    return;
}

void CallGraph::dfs(vector<Function*>& prevs, Function* cur) {
    if (cur->isTag()) { return; }
    prevs.push_back(cur);
    cur->Tag();
    if (cur->getChilds().size() == 0) {
        for (int i = 0; i < prevs.size(); ++i) {
            Function* cur = prevs[i];
            if (!cur->isGened()) { cur->genCorpus(); }
            
            // corpus_.push_back(vector2str(cur->getCorpus()));
        }
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

void CallGraph::genCorpus() {
    vector<Function*> prevs;
    if (root_ == nullptr) { return; }
    dfs(prevs, root_);

    return;
}
