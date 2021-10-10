# -*- coding: utf-8 -*-
# @Author: lichen

import sys, os, socket
from datetime import datetime, date, time
import json, base64, hashlib, re
import threading
import sched
import importlib

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/rules/"%(os.path.dirname(os.path.abspath(__file__))))

import crash
import collect_data
import utils
import unmatched

def query(sn, data):
    ret = {}
    ret['return'] = False
    ret['solution'] = {}
    ret['solution']['io'] = {}
    vmcore_path = ''
    systime = None
    desc_mods = {}
    name_keywords = {}
    name_mods = {}

        for file in files:
            filepath = subdir + os.sep + file
            if os.path.isfile(filepath) and file.endswith('.py') and (
                    file.startswith('IO_')):
                fixup_mod = file[:-3]
                try:
                    mod = importlib.import_module(fixup_mod)
                    keywords = None
                    if hasattr(mod,'get_issue_keywords'):
                        keywords = mod.get_issue_keywords()
                    if keywords and len(keywords) > 0:
                        for keyword in keywords:
                            err_keywords.add(keyword)
                        name_keywords[mod.__name__] = ','.join(keywords)
                        name_mods[mod.__name__] = mod

                    if hasattr(mod,'get_description'):
                        desc = mod.get_description()
                        if len(desc) > 0:
                            if desc not in desc_mods:
                                desc_mods[desc] = []
                            desc_mods[desc].append(mod)
                    
                except Exception as e:
                    print( '%s Exception!'%(mod),e)
                    pass

    i = 1
    index_mods = {}
    input_str = "\n请选择匹配的问题编号:\n"
    for titles in desc_mods:
        input_str = "%s%s.%s\n"%(input_str,i,titles)
        index_mods[i] = desc_mods[titles]
        i += 1
    input_str = "%s%s.%s\n"%(input_str,i,"其它")
    input_str = "%s%s.%s\n"%(input_str,i+1,"全量扫描")

    index = utils.get_input_int(input_str)
    if index == i:
        keywords = utils.get_input_str("\n请输入问题关键字，比如dmesg的错误日志，或者异常关键字，如%s\n"%(','.join(err_keywords)))
        j = 1
        keyword_index_mods = {}
        keyword_str = "\n请选择匹配的问题编号:\n"
        for name in name_keywords:
            if keywords in name_keywords[name]:
                try:
                    keyword_str = "%s%s.%s:%s\n"%(keyword_str,j,name,name_keywords[name])
                    keyword_index_mods[j] = name_mods[name]
                    j += 1
                except:
                    pass
        keyword_str = "%s%s.%s\n"%(keyword_str,j,"其它")
        keyword_str = "%s%s.%s\n"%(keyword_str,j+1,"全量扫描")
        keyword_no = utils.get_input_int(keyword_str)

        if keyword_no == j:
            ret = unmatched.query(sn,data)
        elif keyword_no==(j+1):
            for no in keyword_index_mods:
                try:
                    ret = keyword_index_mods[no].query(sn, data)
                    if ret['return']:
                        result = {keyword_index_mods[no].__name__:ret['solution']}
                        utils.post_ossre_diag(json.dumps(result,ensure_ascii=False))

                except Exception as e:
                    print( '%s Exception!'%(keyword_index_mods[no].__name__),e)
                    pass
        else:
            try:
                ret = keyword_index_mods[keyword_no].query(sn, data)
                if ret['return']:
                    result = {keyword_index_mods[keyword_no].__name__:ret['solution']}
                    utils.post_ossre_diag(json.dumps(result,ensure_ascii=False))

            except Exception as e:
                print( '%s Exception!'%(keyword_index_mods[keyword_no]),e)
                pass
    elif index==(i+1):
        for name in name_mods:
            try:
                ret = name_mods[name].query(sn, data)
                if ret['return']:
                    result = {name:ret['solution']}
                    utils.post_ossre_diag(json.dumps(result,ensure_ascii=False))

            except Exception as e:
                print( '%s Exception!'%(name),e)
                pass
    else:
        for mod in index_mods[index]:
            try:
                ret = mod.query(sn, data)
                if ret['return']:
                    result = {mod.__name__:ret['solution']}
                    utils.post_ossre_diag(json.dumps(result,ensure_ascii=False))

            except Exception as e:
                print( '%s Exception!'%(mod),e)
                pass

    matched = utils.get_input_int("\n请选择编号:\n1.已匹配问题\n2.未匹配问题\n3.退出诊断\n")
    if matched == 2:
        ret = unmatched.query(sn,data)

    print( __name__,':',ret)
    return ret

def main():
    sn = ''
    data = {}
    query(sn, data)

if __name__ == "__main__":
    main()
