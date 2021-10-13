# -*- coding: utf-8 -*-
# @Author: lichen

import sys, os, socket
import time,datetime
import json, base64, hashlib, re
import threading
import sched
import importlib

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/rules/"%(os.path.dirname(os.path.abspath(__file__))))
sys.path.append("%s/vmcore/"%(os.path.dirname(os.path.abspath(__file__))))

import crash
import collect_data
import utils

VMCORE_FUNCS = {
        'VMCORE':['parse_panic']
}

def query(sn, data):
    ret = {}
    ret['solution'] = {}
    ret['solution']['crash'] = {}
    ret['solution']['crash']['local'] = {}

    for func_class in VMCORE_FUNCS:
        for func in VMCORE_FUNCS[func_class]:
            mod = importlib.import_module(func)
            ret1 = mod.query(sn, data)
            if ret1['return']:
                ret['return'] = True
                ret['solution']['crash']['local'] = ret1['solution']

    if ret['return']:
        utils.post_ossre_diag(json.dumps(ret['solution']['crash'],ensure_ascii=False))

    print( __name__,':',ret)
    return ret

def main():
    sn = ''
    data = {}
    query(sn, data)

if __name__ == "__main__":
    main()
