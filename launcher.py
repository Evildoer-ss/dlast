import os
import sys
import json
import time
import subprocess
import ctypes


DEBUG = 0

# TMP_DIR = os.path.join('/Users/ssj/tmp', str(time.time()))
TMP_DIR = os.path.join('/Users/ssj/tmp', '1602256449.093935')
FUNC_PATH = os.path.join(TMP_DIR, 'funcs.json')
FUNC_FIXED_PATH = os.path.join(TMP_DIR, 'funcs_fixed.json')
STR_PATH = os.path.join(TMP_DIR, 'strs.json')
STR_FIXED_PATH = os.path.join(TMP_DIR, 'strs_fixed.json')
CFG_DIR = os.path.join(TMP_DIR, 'cfgs')
CFG_FIXED_PATH = os.path.join(TMP_DIR, 'cfg_fixed.json')
CG_PATH = os.path.join(TMP_DIR, 'cg.json')
CG_FIXED_PATH = os.path.join(TMP_DIR, 'cg_fixed.json')

if not os.path.dirname(sys.argv[0]): PROJ_ROOT_PATH = os.getcwd()
else: PROJ_ROOT_PATH = os.path.abspath(os.path.dirname(sys.argv[0]))
TOOLS_IBLESSING = os.path.join(PROJ_ROOT_PATH, 'tools', 'iblessing-darwin')

if not os.path.exists(TMP_DIR): os.makedirs(TMP_DIR)
if not os.path.exists(CFG_DIR): os.makedirs(CFG_DIR)


def run_cmd(cmd):
    if DEBUG: return
    os.system(cmd)

class Radare2:
    def __init__(self, binary_path):
        if DEBUG: return
        self.pipe = subprocess.Popen(['r2', '-A', binary_path], stdin=subprocess.PIPE)
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
        open('/tmp/tmptest.txt', 'w').write(a)
        func_list = json.loads(a)
        fixed_dict = {}
        for it in func_list:
            fixed_dict[it['offset']] = it['name']
        open(FUNC_FIXED_PATH, 'w').write(json.dumps(fixed_dict))
        return fixed_dict

    @staticmethod
    def fix_cfg_json(addr2str, addr2func, func2id):
        fixed_dict = {}
        for func_addr in addr2func.keys():
            if addr2func[func_addr] not in func2id.keys(): continue
            cur_cfg = json.loads(open(os.path.join(CFG_DIR, str(func_addr) + '.json')).read())[0]
            cur_cfg_fixed = {'blocks': [], 'name': addr2func[func_addr]}
            for block in cur_cfg['blocks']:
                block_fixed = {}
                block_fixed['offset'] = block['offset']
                block_fixed['jump'] = block['jump'] if 'jump' in block.keys() else -1
                block_fixed['fail'] = block['fail'] if 'fail' in block.keys() else -1
                block_fixed['refs'] = []
                for op in block['ops']:
                    if 'refs' not in op.keys(): continue
                    block_fixed['refs'] += [addr2str[it['addr']] for it in op['refs'] if it['type'] == 'DATA' and it['addr'] in addr2str.keys()]
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
                cur_dict['callee'].append(callee['id'])
            fixed_cg.append(cur_dict)
        open(CG_FIXED_PATH, 'w').write(json.dumps(fixed_cg))
        return func2id

def generate_fixed_json_file(binary_path):
    r2 = Radare2(binary_path)
    r2.send('aflj > ' + FUNC_PATH)
    r2.send('izj > ' + STR_PATH)

    while not os.path.exists(STR_PATH) or not os.path.exists(FUNC_PATH): time.sleep(8)
    r2.sendline()

    addr2str = FixFuncs.fix_strs_json()
    addr2func = FixFuncs.fix_funcs_json()

    run_cmd('%s -m scan -i objc-msg-xref -f %s -o %s' % (TOOLS_IBLESSING, binary_path, TMP_DIR))
    out_file = os.path.join(TMP_DIR, '%s_method-xrefs.iblessing.txt' % (os.path.basename(binary_path)))
    if not os.path.exists(out_file): return
    run_cmd('%s -m generator -i objc-msg-xref-json -f %s -o %s' % (TOOLS_IBLESSING, out_file, TMP_DIR))
    out_file += '_objc_msg_xrefs.iblessing.json'
    if not os.path.exists(out_file): return
    run_cmd('mv %s %s' % (out_file, CG_PATH))

    func2id = FixFuncs.fix_cg_json()

    for func_addr in addr2func.keys():
        r2.send('s ' + str(func_addr))
        r2.send('agfj > ' + os.path.join(CFG_DIR, str(func_addr) + '.json'))

    # to fix
    time.sleep(2)
    r2.quit()
    r2.sendline()

    FixFuncs.fix_cfg_json(addr2str, addr2func, func2id)

def main():
    binary_path = sys.argv[1]

    generate_fixed_json_file(binary_path)

    # helper_lib = ctypes.CDLL(os.path.join(PROJ_ROOT_PATH, 'libs', 'libhelper.dylib'))
    # helper_lib.GenerateCorpus(TMP_DIR.encode())


if __name__ == '__main__':
    if len(sys.argv) < 2: sys.exit('Usage')
    if len(sys.argv) == 3: DEBUG = 1

    start_time = time.time()

    main()

    print(time.time() - start_time)
