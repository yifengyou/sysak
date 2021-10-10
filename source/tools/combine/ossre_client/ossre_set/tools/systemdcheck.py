# -*- coding: utf-8 -*-
# @Author: shiyan

import os
import sys
import datetime,time
import subprocess
import re
import socket
import json
import traceback
import importlib
import loadcheck,semcheck,rwsemcheck,mutexcheck,alidiagnose,perf
from time import sleep

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
import utils
import collect_data

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

def main():
    sn = ''
    data = {}
    ret = {}
    ret['return'] = False
    ret['solution'] = {}
    ret['solution']['detail'] = []
    ret['solution']['summary'] = ''
    hotfix = ''

    try:
        for subdir, dirs, files in os.walk("%s/../rules"%(os.path.dirname(os.path.abspath(__file__)))):
            for file in files:
                filepath = subdir + os.sep + file
                if os.path.isfile(filepath) and file.endswith('.py'):
                    rule_mod = file[:-3]
                    try:
                        mod = importlib.import_module(rule_mod)
                        if (hasattr(mod, "get_category") and mod.get_category()=="systemd"):
                            print( filepath)
                            result = mod.query(sn, data)
                            if result['return']:
                                ret['return'] = True
                                ret['solution']['detail'].append(result)
                                ret['solution']['summary'] += ("%s\n"%(result['solution']))
                    except Exception as e:
                        traceback.print_exc()
                        pass
        if len(ret['solution']['summary']) <= 0:
            ret['solution']['summary'] = '未发现异常'
        print json.dumps(ret,ensure_ascii=False)
        f = open("/tmp/systemdcheck.log", "w+")
        f.write(json.dumps(ret,ensure_ascii=False))
        f.close()
    except:
        ret['solution']['summary'] += "解析异常！\n"
        f = open("/tmp/systemdcheck.log", "w+")
        f.write(json.dumps(ret,ensure_ascii=False))
        f.close()
        traceback.print_exc()
        print "systemdcheck exception!"

if __name__ == "__main__":
    if os.path.isfile("/tmp/systemdcheck.log"):
        cmd = 'echo "" > /tmp/systemdcheck.log'
        output = os.popen(cmd)
        output.close()
        print "/tmp/systemdcheck.log exist"
    else:
        print "/tmp/systemdcheck.log not exist"
    main()
            
