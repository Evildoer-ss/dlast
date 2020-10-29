# coding: utf-8

import os
import sys
import json
import time
import frida


TEST = 0
TMP_DIR = None
IS_GET_IGNORED_METHODS = False
IGNORED_METHODS = []


attach_func = '''
method = ObjC.classes["{0}"]["{1}"];
if (method != undefined) {{
    Interceptor.attach(method.implementation, {{
        onEnter: function (args) {{
            method_dict["{0} {1}"] = 1;
        }},
        onLeave: function (retVal) {{
        }}
    }})
}}

'''

JS_CODE = '''
var method;
var method_dict = {};

rpc.exports = {
    getMethodDict: function() {
        send(method_dict);
    },
    clearMethodDict: function() {
        method_dict = {};
    },
    openurl: function (url) {
        var w = ObjC.classes.LSApplicationWorkspace.defaultWorkspace();
        var toOpen = ObjC.classes.NSURL.URLWithString_(url);
        method_dict["cur_scheme_url"] = url;
        method_dict["is_openurl_success"] = w.openSensitiveURL_withOptions_(toOpen, null);
        return;
    }
};
'''

def get_process_name(bundleID):
    for line in os.popen('frida-ps -Uai').readlines():
        if bundleID in line:
            tgt_list = line.split(' ')
            while '' in tgt_list:
                tgt_list.remove('')
            return tgt_list[1]
    # return '飞书'
    print('Not found APP name by bundleID: %s' % bundleID)
    sys.exit(1)

def generate_frida_script():
    global JS_CODE

    addr2name = json.loads(open(os.path.join(TMP_DIR, 'funcs_fixed.json')).read())
    addr_list = open('/tmp/radare2_useful_funclist.ssj').read().split('\n')
    while '' in addr_list: addr_list.remove('')

    for addr in addr_list:
        name = addr2name[addr]
        if name.startswith('method.class'):
            method_name += '+ '
            class_name = name[name.find('method.class.') + len('method.class.') : name.rfind('.')]
        else:
            method_name = '- '
            class_name = name[name.find('method.') + len('method.') : name.rfind('.')]
        method_name += name[name.rfind('.') + 1 :]
        # method_name += ':'
        JS_CODE += attach_func.format(class_name, method_name)

    open(os.path.join(TMP_DIR, 'frida_script.js'), 'w').write(JS_CODE)

def fuzz_test_url(script):
    url_list = [
        'lark://applink.feishu.cn/client/mini_program/open?appId=1234567890&mode=window',
        'lark://applink.feishu.cn/client/chat/open?openId=1234567890',
        'lark://sdlfkjhgh',
        'lark://fromaccount_manager',
        'lark://applink.feishu.cn/client/web_app/open?appId=xxx&path=/a/b&xxd=123'
    ]
    for url in url_list:
        script.exports.openurl(url)
        time.sleep(1)
        script.exports.get_method_dict()
        time.sleep(0.2)
        script.exports.clear_method_dict()


def fuzz(tmp_dir, bundleID):
    name = get_process_name(bundleID)
    global TMP_DIR, JS_CODE
    TMP_DIR = tmp_dir
    print('Generating frida script...')
    generate_frida_script()

    print('%s Start fuzzing...' % str(time.asctime(time.localtime(time.time()))))

    fresult = open(os.path.join(TMP_DIR, 'result.txt'), 'w')

    def dump_trace(trace_info):
        if trace_info['is_openurl_success'] == False: return
        global IGNORED_METHODS
        fresult.write('[# %d] %s\n' % (len(set(list(trace_info.keys())).difference(set(IGNORED_METHODS))), trace_info['cur_scheme_url']))
        for key, value in trace_info.items():
            if value == 0 or key in IGNORED_METHODS: continue
            fresult.write(key + '\n')

    def on_message(message, data):
        if message['type'] == 'send':
            global IS_GET_IGNORED_METHODS
            if IS_GET_IGNORED_METHODS == False:
                global IGNORED_METHODS
                IGNORED_METHODS = list(message['payload'])
                IGNORED_METHODS.append('is_openurl_success')
                IGNORED_METHODS.append('cur_scheme_url')
                IS_GET_IGNORED_METHODS = True
                return
            dump_trace(message['payload'])
        elif message['type'] == 'error':
            print(message['description'])
        else:
            print(message)

    process = frida.get_usb_device().attach(name)
    script = process.create_script(JS_CODE)
    script.on('message', on_message)
    script.load()

    # Exclude methods that are constantly being called.
    time.sleep(5)
    script.exports.get_method_dict()
    time.sleep(1)
    script.exports.clear_method_dict()

    if TEST: fuzz_test_url(script)

    corpus_list = open(os.path.join(TMP_DIR, 'corpus.txt')).readlines()
    urlscheme_list = json.loads(open(os.path.join(TMP_DIR, 'URLSchemes.json')).read())
    curid, length = 0, len(corpus_list)
    for url in corpus_list:
        if curid % 10 == 0:
            print('\r%d / %d' % (curid, length), end='', flush=True)
        curid += 1
        for urlscheme in urlscheme_list:
            script.exports.openurl(urlscheme + '://' + url.strip())
            time.sleep(0.1)
            script.exports.get_method_dict()
            time.sleep(0.1)
            script.exports.clear_method_dict()
        if TEST: break
    print('\r%d / %d' % (length, length), end='', flush=True)
    print('')

    time.sleep(1)
    script.unload()
    fresult.close()

    print(os.path.join(TMP_DIR, 'result.txt'))


if __name__ == "__main__":
    if len(sys.argv) > 1: TEST = 1
    fuzz('/Users/ssj/tmp/1603959499.56307', '飞书')
