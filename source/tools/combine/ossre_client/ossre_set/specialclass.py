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

sys.path.append("%s/vmcore"%(os.path.dirname(os.path.abspath(__file__))))
sys.path.append("%s/rules"%(os.path.dirname(os.path.abspath(__file__))))

import unmatched
#import memleak
#import oomissue
#logger = utils.get_logger()

def query(sn, data):
    data = {}
    sn = ''
    ret = {}
    ret['return'] = False
    ret['solution'] = {}

    subsys = raw_input("请选择专项问题类型编号:\n1.内存泄漏\n2.OOM\n"
		"3.不确定类型问题\n")
    try:
        subsys = int(subsys)
    except:
        subsys = raw_input("输入错误，请选择问题类型编号数字:")
        subsys = int(subsys)
        pass
    #if subsys == 1:
    #    ret = memleak.query(sn, data)
    #elif subsys == 2:
    #    ret = oomissue.query(sn, data)
    #elif subsys == 3:
    #    ret = spec_misc.query(sn, data)

    matched = utils.get_input_int("\n请选择编号:\n1.已匹配问题\n2.未匹配问题\n3.退出诊断\n")
    if matched == 2:
        ret = unmatched.query(sn,data)

    print (__name__,':',ret)
    return ret

def main():
    sn = ''
    data = {}
    query(sn, data)

if __name__ == "__main__":
    main()
