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

sys.path.append("%s/vmcore"%(os.path.dirname(os.path.abspath(__file__))))
sys.path.append("%s/rules"%(os.path.dirname(os.path.abspath(__file__))))

import highsys
import highload
import hangissue
import schedissue
import memissue
import ioissue
import netissue
import miscissue
import crashissue
import specialclass

#logger = utils.get_logger()

def query(args):
    data = {}
    sn = ''
    ret = {}
    ret['return'] = False
    ret['solution'] = {}

    run_offline = 0
    parser = argparse.ArgumentParser()
    parser.add_argument('-o','--offline', action='store_true', help='run in offline, no network available.')
    args = vars(parser.parse_args())
    if args.get('offline',False) == True:
        run_offline = 1
    os.environ['run_offline']=str(run_offline)

    print ("请注意：工具尝试检查机器是否存在已知OS问题，并推荐已知问题的解决方案，\n"
           "请在部署推荐方案前联系内核支持同学确认方案的正确性！\n")

    subsys = raw_input("请选择问题类型编号:\n1.sys高\n2.load高\n3.宕机\n4.夯机\n"
		"5.调度类问题\n6.内存类问题\n7.FS/IO问题\n8.网络问题\n"
        "9.定界问题\n10.专项问题\n11.不确定类型问题\n")
    try:
        subsys = int(subsys)
    except:
        subsys = raw_input("输入错误，请选择问题类型编号数字:")
        subsys = int(subsys)
        pass

    if subsys == 1:
        ret = highsys.query(sn, data)
    elif subsys == 2:
        ret = highload.query(sn, data)
    elif subsys == 3:
        ret = crashissue.query(sn, data)
    elif subsys == 4:
        ret = hangissue.query(sn, data)
    elif subsys == 5:
        ret = schedissue.query(sn, data)
    elif subsys == 6:
        ret = memissue.query(sn, data)
    elif subsys == 7:
        ret = ioissue.query(sn, data)
    elif subsys == 8:
        ret = netissue.query(sn, data)
    #elif subsys == 9:
    #    ret = classification.query(sn, data)
    elif subsys == 10:
        ret = specialclass.query(sn, data)
    elif subsys == 11:
        ret = miscissue.query(sn, data)
    if ret['return']:
        print( "\n\n匹配到已知问题，请查看如下匹配结果!")
        print( ret)
    else:
        print( "\n\n未匹配到已知问题，请联系内核支持!")

def main():
    query(sys.argv)

if __name__ == "__main__":
    main()
