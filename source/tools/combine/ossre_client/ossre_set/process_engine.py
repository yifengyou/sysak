# -*- coding: utf-8 -*-
# @Author: lichen

import sys,os,socket
import time,datetime
import json,base64,hashlib,re
import threading
import sched
import importlib
import utils
import crash
import json
import argparse
import traceback

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

sys.path.append("%s/vmcore"%(os.path.dirname(os.path.abspath(__file__))))
sys.path.append("%s/rules"%(os.path.dirname(os.path.abspath(__file__))))

VMCORE_FUNCS = {
        'VMCORE':['parse_panic']
}

"""
We define a unique ID for every rule,
SCHED rules use 1000-1999
MEM rules use 2000-2999
IO rules use 3000-3999
NET rules use 4000-4999
MISC rules use 5000-5999
Please add the rule ID in rule file name, and we also
would like you to add reproducers in ../repro folder named with rule ID.
"""
ONLINE_FUNCS = ['SCHED',
        'MEM',
        'IO',
        'NET',
        'MISC']
SYS_CHECK = 'syscheck.py'
logger = utils.get_logger()

def query(bysyscheck=0,crashonly=0,data=None):
    run_all = 0
    run_offline = 0
    run_fast = 1
    run_silent = 0
    run_crash = crashonly

    run_all = os.environ.get('run_all')
    if run_all is None or int(run_all) != 1:
        run_all = 0
    run_silent = os.environ.get('run_silent')
    if run_silent is None or int(run_silent) != 1:
        run_silent = 0
    run_offline = os.environ.get('run_offline')
    if run_offline is None or int(run_offline) != 1:
        run_offline = 0

    parser = argparse.ArgumentParser()
    parser.add_argument('-a','--all', action='store_true', help='run all rules including cases need input, need more time to finish.')
    parser.add_argument('-o','--offline', action='store_true', help='run in offline, no network available.')
    args = vars(parser.parse_args())
    if args.get('all',False) == True:
        run_all = 1
        run_fast = 0
    if args.get('offline',False) == True:
        run_offline = 1
    args, left = parser.parse_known_args()
    sys.argv = sys.argv[:1]+left

    if crashonly == 1:
        run_crash = 1
    if run_all == 1:
        run_fast = 0

    if data is None:
        data = {}
    data["run_all"] = run_all
    data["run_fast"] = run_fast
    data["run_offline"] = run_offline
    data["run_crash"] = run_crash
    os.environ['run_all']=str(run_all)
    os.environ['run_fast']=str(run_fast)
    os.environ['run_offline']=str(run_offline)
    os.environ['run_silent']=str(run_silent)
    os.environ['run_crash']=str(run_crash)

    sn = ''
    rets = {}
    rets['issue_result'] = {}
    ret = {}
    ret['return'] = False
    ret['solution'] = {}
    all_matched = {}
    all_matched['PANIC'] = []
    mods = []

    if run_silent == 0:
        print("请注意：工具尝试检查机器是否存在已知OS问题，并推荐已知问题的解决方案，\n"
           "请在部署推荐方案前联系内核同学确认方案的正确性！\n")

    # check vmcores
    for func_class in VMCORE_FUNCS:
        for func in VMCORE_FUNCS[func_class]:
            if bysyscheck == 1 and crashonly == 0:
                continue
            mod = importlib.import_module(func)
            ret = mod.query(sn, data, crashonly=crashonly)
            if ret['solution']:
                if all_matched.get('PANIC') is None:
                    all_matched['PANIC'] = []
                all_matched['PANIC'].append(ret['solution'])

    # check online issues
    try:
        for func_class in ONLINE_FUNCS:
            for subdir, dirs, files in os.walk("%s/rules"%(os.path.dirname(os.path.abspath(__file__)))):
                for file in files:
                    filepath = subdir + os.sep + file
                    if os.path.isfile(filepath) and (file.startswith('%s_'%(func_class))):
                        if file.endswith('.py'):
                            rule_mod = file[:-3]
                        else:
                            continue
                        if rule_mod not in mods:
                            mods.append(rule_mod)
                        else:
                            continue
                        try:
                            mod = importlib.import_module(rule_mod)
                            if (crashonly == 1):
                                if (not hasattr(mod, "has_crashonly_mode") or  not mod.has_crashonly_mode()):
                                    continue
                            elif (run_all == 0 and ((hasattr(mod, "need_high_res") and mod.need_high_res())
                                or (hasattr(mod, "need_input") and mod.need_input())
                                or (hasattr(mod, "need_long_time") and mod.need_long_time()))):
                                continue
                            #print("%s start>"%(mod.__name__))
                            ret = mod.query(sn, data)
                            #print("%s end>"%(mod.__name__))
                            rets['issue_result'][rule_mod] = {}
                            rets['issue_result'][rule_mod] = ret
                            if ret is not None and ret['return']:
                                if all_matched.get('online') is None:
                                    all_matched['online'] = {}
                                    all_matched['cust'] = {}

                                if all_matched['online'].get(func_class) is None:
                                    all_matched['online'][func_class] = []
                                all_matched['online'][func_class].append(ret['solution'])
                                cust = {}
                                cust['category'] = func_class
                                cust['name'] = mod.__name__
                                cust['desc'] = ""
                                if (hasattr(mod, "get_description")):
                                    cust['desc'] = mod.get_description()
                                cust['solution'] = ret['solution']
                                cust['summary'] = ret['solution']
                                if (not hasattr(mod, "get_severe_level")):
                                    cust['level'] = 'error'
                                else:
                                    level = mod.get_severe_level()
                                    cust['level'] = level
                                all_matched['cust'][mod.__name__] = cust
                        except Exception as e:
                            print( '%s Exception!'%(mod),e)
                            traceback.print_exc()
                            pass

    except Exception as e:
        print( 'ossre Exception!',e)
    result = {'process_engine':all_matched}
    if bysyscheck != 1:
        logger.write(json.dumps(result,ensure_ascii=False))
        logger.write('\nossre_done')
    ret = json.dumps(all_matched,ensure_ascii=False)
    if run_silent == 0:
        print( ret)
    if bysyscheck != 1:
        utils.post_ossre_diag(ret)
    rets['all_matched'] = all_matched
    return rets

def main():
    query()

if __name__ == "__main__":
    main()
