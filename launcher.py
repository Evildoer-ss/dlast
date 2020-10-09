import os
import sys
import json
import time
import subprocess

TMP_DIR = os.path.join('/tmp', str(time.time()))
FUNC_PATH = os.path.join(TMP_DIR, 'funcs.json')
FUNC_FIXED_PATH = os.path.join(TMP_DIR, 'funcs_fixed.json')
STR_PATH = os.path.join(TMP_DIR, 'strs.json')
STR_FIXED_PATH = os.path.join(TMP_DIR, 'strs_fixed.json')
CFG_DIR = os.path.join(TMP_DIR, 'cfgs')
CFG_FIXED_PATH = os.path.join(TMP_DIR, 'cfg_fixed.json')

if not os.path.exists(TMP_DIR): os.makedirs(TMP_DIR)
if not os.path.exists(CFG_DIR): os.makedirs(CFG_DIR)


class Radare2:
    def __init__(self, binary_path):
        self.pipe = subprocess.Popen(['r2', '-AA', binary_path], stdin=subprocess.PIPE)
    def send(self, cmd):
        self.pipe.stdin.write(cmd.encode('utf-8'))
        self.pipe.stdin.write(b'\n')
        self.pipe.stdin.flush()
    def wait(self):
        self.pipe.wait()
    def quit(self):
        self.pipe.terminate()

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
        func_list = json.loads(open(FUNC_PATH).read())
        fixed_dict = {}
        for it in func_list:
            fixed_dict[it['offset']] = it['name']
        open(FUNC_FIXED_PATH, 'w').write(json.dumps(fixed_dict))
        return fixed_dict
    def fix_cfg_json(addr2str, addr2func):
        fixed_dict = {}
        for func_addr in addr2func.keys():
            cur_cfg = json.loads(open(os.path.join(CFG_DIR, str(func_addr) + '.json')).read())[0]
            cur_cfg_fixed = []
            for block in cur_cfg['blocks']:
                block_fixed = {}
                block_fixed['offset'] = block['offset']
                block_fixed['jump'] = block['jump'] if 'jump' in block.keys() else -1
                block_fixed['fail'] = block['fail'] if 'fail' in block.keys() else -1
                block_fixed['refs'] = []
                for op in block['ops']:
                    if 'refs' not in op.keys(): continue
                    block_fixed['refs'] += [addr2str[it['addr']] for it in op['refs'] if it['type'] == 'DATA']
                cur_cfg_fixed.append(block_fixed)
            fixed_dict[addr2func[func_addr]] = cur_cfg_fixed
        open(CFG_FIXED_PATH, 'w').write(json.dumps(fixed_dict))
        # print(fixed_dict)

def main():
    if len(sys.argv) < 2: sys.exit('Usage')
    
    binary_path = sys.argv[1]

    r2 = Radare2(binary_path)
    r2.send('izj > ' + STR_PATH)
    r2.send('aflj > ' + FUNC_PATH)

    while not os.path.exists(STR_PATH) or not os.path.exists(FUNC_PATH): time.sleep(2)

    addr2str = FixFuncs.fix_strs_json()
    addr2func = FixFuncs.fix_funcs_json()

    for func_addr in addr2func.keys():
        r2.send('s ' + str(func_addr))
        r2.send('agfj > ' + os.path.join(CFG_DIR, str(func_addr) + '.json'))
    
    # to fix
    time.sleep(2)

    FixFuncs.fix_cfg_json(addr2str, addr2func)


if __name__ == '__main__':
    start_time = time.time()

    main()

    print(time.time() - start_time)
