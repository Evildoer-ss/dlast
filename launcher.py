# coding: utf-8

import os
import sys
import json
import time
import subprocess
import ctypes
import argparse

from src.utils.fuzzer import fuzz


DEBUG = 0

TMP_DIR = os.path.join('/Users/ssj/tmp', str(time.time()))
# TMP_DIR = os.path.join('/Users/ssj/tmp', '1603182172.931805')
FUNC_PATH = os.path.join(TMP_DIR, 'funcs.json')
FUNC_FIXED_PATH = os.path.join(TMP_DIR, 'funcs_fixed.json')
STR_PATH = os.path.join(TMP_DIR, 'strs.json')
STR_FIXED_PATH = os.path.join(TMP_DIR, 'strs_fixed.json')
# CFG_DIR = os.path.join(TMP_DIR, 'cfgs')
CFG_PATH = os.path.join(TMP_DIR, 'cfg.json')
CFG_FIXED_PATH = os.path.join(TMP_DIR, 'cfg_fixed.json')
CG_PATH = os.path.join(TMP_DIR, 'cg.json')
CG_FIXED_PRE_PATH = os.path.join(TMP_DIR, 'cg_fixed_pre.json')
CG_FIXED_PATH = os.path.join(TMP_DIR, 'cg_fixed.json')

EXISTED_CG_PATH = None

if not os.path.dirname(sys.argv[0]): PROJ_ROOT_PATH = os.getcwd()
else: PROJ_ROOT_PATH = os.path.abspath(os.path.dirname(sys.argv[0]))
TOOLS_IBLESSING = os.path.join(PROJ_ROOT_PATH, 'tools', 'iblessing-darwin')

if not os.path.exists(TMP_DIR): os.makedirs(TMP_DIR)


def run_cmd(cmd):
    if DEBUG: return
    os.system(cmd)

def get_args():
    parser = argparse.ArgumentParser(description="DLAST")
    parser.add_argument("-i", "--input", type=str)
    parser.add_argument('-o', '--output', type=str)
    parser.add_argument("-d", "--debug", action="store_true",)
    parser.add_argument("binary", type=str)
    return parser.parse_args()

class Radare2:
    def __init__(self, binary_path):
        if DEBUG: return
        self.pipe = subprocess.Popen(['r2', binary_path], stdin=subprocess.PIPE)
    def send(self, cmd):
        if DEBUG: return
        self.pipe.stdin.write(cmd.encode('utf-8'))
        self.pipe.stdin.write(b'\n')
        self.pipe.stdin.flush()
    def sendline(self):
        if DEBUG: return
        self.pipe.stdin.write(b'\n')
        self.pipe.stdin.flush()
    def quit(self):
        if DEBUG: return
        self.pipe.stdin.write(b'q\n')
        self.pipe.stdin.flush()
        while subprocess.Popen.poll(self.pipe) == None: time.sleep(5)

class FixFuncs:
    @staticmethod
    def fix_strs_json():
        str_list = json.loads(open(STR_PATH).read())
        fixed_dict = {}
        for it in str_list:
            fixed_dict[it['vaddr']] = it['string']
        open(STR_FIXED_PATH, 'w').write(json.dumps(fixed_dict))
        return fixed_dict

    @staticmethod
    def fix_funcs_json():
        print(FUNC_PATH)
        a = open(FUNC_PATH).read()
        func_list = json.loads(a)
        fixed_dict = {}
        for it in func_list:
            fixed_dict[it['offset']] = it['name']
        open(FUNC_FIXED_PATH, 'w').write(json.dumps(fixed_dict))
        return fixed_dict

    @staticmethod
    def fix_cfg_json(addr2str, addr2func, func2id):
        # eliminate single comma
        raw_cfg = open(CFG_PATH).readlines()
        while ',\n' in raw_cfg: raw_cfg.remove(',\n')
        raw_cfg = json.loads(''.join(raw_cfg))

        fixed_dict = {}
        for cur_cfg in raw_cfg:
            func_addr = cur_cfg['offset']
            if func_addr not in addr2func.keys(): continue
            if addr2func[func_addr] not in func2id.keys(): continue
            # cur_cfg_fixed = {'blocks': [], 'name': addr2func[func_addr]}
            cur_cfg_fixed = {'blocks': [], 'name': cur_cfg['name']}
            for block in cur_cfg['blocks']:
                block_fixed = {}
                block_fixed['offset'] = block['offset']
                block_fixed['jump'] = block['jump'] if 'jump' in block.keys() else -1
                block_fixed['fail'] = block['fail'] if 'fail' in block.keys() else -1
                block_fixed['refs'] = []
                for op in block['ops']:
                    if 'refs' not in op.keys(): continue
                    # Why ssj writes this line fucking long. -- ssj
                    block_fixed['refs'] += [addr2str[it['addr']][len('cstr.'):] for it in op['refs'] if it['type'] == 'DATA' and it['addr'] in addr2str.keys() and addr2str[it['addr']].startswith('cstr.')]
                    # block_fixed['refs'] += [addr2str[it['addr']] for it in op['refs'] if it['type'] == 'DATA' and it['addr'] in addr2str.keys()]
                cur_cfg_fixed['blocks'].append(block_fixed)
            fixed_dict[func2id[addr2func[func_addr]]] = cur_cfg_fixed
        open(CFG_FIXED_PATH, 'w').write(json.dumps(fixed_dict))
        # print(fixed_dict)

    @staticmethod
    def fix_cg_json():
        raw_cg = json.loads(open(CG_PATH, 'r').read())
        fixed_cg = []
        func2id = {}
        for func in raw_cg['methods']:
            sel = func['sel']
            name_ret = sel[sel.find('[') + 1: sel.find(' ')]
            name_fun = sel[sel.find(' ') + 1: sel.find(']')]
            if sel.startswith('-'): name = 'method.%s.%s' % (name_ret, name_fun)
            elif sel.startswith('+'): name = 'method.class.%s.%s' % (name_ret, name_fun)
            else: continue

            func2id[name] = func['id']
            cur_dict = {}
            cur_dict['id'] = func['id']
            cur_dict['name'] = name
            cur_dict['callee'] = []
            for callee in func['postMethods']:
                if callee['id'] not in cur_dict['callee']: cur_dict['callee'].append(callee['id'])
            
            fixed_cg.append(cur_dict)
        open(CG_FIXED_PRE_PATH, 'w').write(json.dumps(fixed_cg))
        return func2id

def generate_useful_funclist(func2id, addr2func, cg_fixed_path=CG_FIXED_PRE_PATH):
    root_func = 'openURL'
    # root_func = 'method.AppDelegate.application:openURL:options:'
    # method.AppContainer.AppDelegate.application:openURL:options:
    queue = []
    func_id_list = []
    fixed_items = []
    cg_list = json.loads(open(cg_fixed_path).read())
    for it in cg_list:
        if root_func in it['name']:
            queue.append(it)
            func_id_list.append(it['id'])
            fixed_items.append(it)
            # break

    cg_dict = {}
    for it in cg_list:
        cg_dict[it['id']] = {'name': it['name'], 'callee': it['callee']}

    while queue:
        cur_it = queue[0]
        queue.pop(0)
        for it_id in cur_it['callee']:
            if it_id in func_id_list: continue
            if it_id not in cg_dict.keys(): continue
            it = cg_dict[it_id]
            it['id'] = it_id
            queue.append(it)
            func_id_list.append(it_id)
            fixed_items.append(it)
    open(CG_FIXED_PATH, 'w').write(json.dumps(fixed_items, indent=4))

    print(len(func_id_list))

    id2func = {}
    func2addr = {}
    for key, val in func2id.items(): id2func[val] = key
    for key, val in addr2func.items(): func2addr[val] = key
    fd = open('/tmp/radare2_useful_funclist.ssj', 'w')
    for it in func_id_list:
        if it not in id2func.keys(): continue
        if id2func[it] not in func2addr.keys(): continue
        fd.write(str(func2addr[id2func[it]]))
        fd.write('\n')

def generate_fixed_json_file(binary_path):
    r2 = Radare2(binary_path)
    r2.send('aa')
    r2.send('aflj > ' + FUNC_PATH)
    r2.send('izj > ' + STR_PATH)

    while not os.path.exists(STR_PATH) or not os.path.exists(FUNC_PATH): time.sleep(2)
    r2.sendline()
    time.sleep(1)

    addr2str = FixFuncs.fix_strs_json()
    addr2func = FixFuncs.fix_funcs_json()

    if EXISTED_CG_PATH is None:
        run_cmd('%s -m scan -i objc-msg-xref -f %s -o %s' % (TOOLS_IBLESSING, binary_path, TMP_DIR))
        out_file = os.path.join(TMP_DIR, '%s_method-xrefs.iblessing.txt' % (os.path.basename(binary_path)))
        if not os.path.exists(out_file): print('warning: %s', out_file)
        run_cmd('%s -m generator -i objc-msg-xref-json -f %s -o %s' % (TOOLS_IBLESSING, out_file, TMP_DIR))
        out_file += '_objc_msg_xrefs.iblessing.json'
        if not os.path.exists(out_file): print('warning: %s', out_file)
        run_cmd('mv %s %s' % (out_file, CG_PATH))
    else: os.system('cp %s %s' % (EXISTED_CG_PATH, TMP_DIR))

    func2id = FixFuncs.fix_cg_json()
    generate_useful_funclist(func2id, addr2func)

    time.sleep(1)
    # for func_addr in addr2func.keys():
    #     r2.send('s ' + str(func_addr))
    r2.send('aaa')
    r2.send('echo [ > ' + CFG_PATH)
    r2.send('agfj >> ' + CFG_PATH)
    r2.send('echo ] >> ' + CFG_PATH)

    # to fix
    while not os.path.exists(CFG_PATH): time.sleep(5)
    while os.path.getsize(CFG_PATH) == 0: time.sleep(5)
    r2.quit()

    FixFuncs.fix_cfg_json(addr2str, addr2func, func2id)

def main():
    global DEBUG, EXISTED_CG_PATH

    args = get_args()
    if os.path.exists(args.binary) and os.path.isfile(args.binary):
        binary_path = args.binary
    else:
        print('input file???')
        sys.exit(1)
    if args.debug: DEBUG = 1
    if args.input:
        if os.path.exists(args.input) and os.path.isfile(args.input):
            EXISTED_CG_PATH = args.input
        else:
            print('[-i] must be a existed file.')
            sys.exit(1)

    generate_fixed_json_file(binary_path)

    helper_lib = ctypes.CDLL(os.path.join(PROJ_ROOT_PATH, 'libs', 'libhelper.dylib'))
    helper_lib.GenerateCorpus(TMP_DIR.encode())

    fuzz(TMP_DIR)


if __name__ == '__main__':
    start_time = time.time()

    try:
        main()
    except Exception as e:
        import traceback
        print(traceback.print_exc())
    finally:
        print(time.time() - start_time)
