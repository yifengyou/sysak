# -*- coding: utf-8 -*-
# @Author: changjun

import sys, os, socket
import time,datetime
import json, base64, hashlib, re
import threading
import sched
import subprocess
import traceback
import importlib

if sys.version[0] == '2':
    import thread
else:
    import _thread as thread

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append("%s/../"%(os.path.dirname(os.path.abspath(__file__))))
sys.path.append("%s/../vmcore"%(os.path.dirname(os.path.abspath(__file__))))
sys.path.append("%s/../rules"%(os.path.dirname(os.path.abspath(__file__))))
import collect_data
import crash
import utils

trace_event = True 
functions = []


if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')

def query(sn, data):
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
                        if (hasattr(mod, "get_category") and mod.get_category()=="memleak"):
                            print( filepath)
                            result = mod.query(sn, data)
                            if result['return']:
                                ret['return'] = True
                                ret['solution']['detail'].append(result)
                                ret['solution']['summary'] += ("%s\n"%(result['solution']))
                    except Exception as e:
                        print( '%s Exception!'%(mod),e)
                        traceback.print_exc()
                        pass

    except Exception as e:
        traceback.print_exc()
        pass
    run_fast = os.environ.get('run_fast')
    if run_fast is not None and int(run_fast) == 1:
        run_fast = True
    else:
        run_fast = False
    if (len(ret['solution']['summary']) <= 0) and not run_fast:
        res = check_memleak(10, 800 * 100 * 100, 0, 150)
        if len(res) > 10:
            ret['result'] = True
            ret['solution']['summary'] = res

    if len(ret['solution']['summary']) <= 0:
        ret['solution']['summary'] = '未发现异常'
    run_silent = os.environ.get('run_silent')
    if run_silent is None or int(run_silent) != 1:
        print( __name__,':',ret)
    return ret

def main():
    sn = ''
    data = {}

    if os.path.isfile("/tmp/memleakcheck.log"):
        cmd = 'echo "" > /tmp/memleakcheck.log'
        output = os.popen(cmd)
        output.close()
        print "/tmp/memleakcheck.log exist"
    else:
        print "/tmp/memleakcheck.log not exist"

    ret = query(sn, data)
    if ret['return']:
        result = {os.path.basename(__file__)[:-3]:ret['solution']}
        utils.post_ossre_diag(json.dumps(result,ensure_ascii=False))

    result_file = json.dumps(ret,ensure_ascii=False)
    f = open("/tmp/memleakcheck.log", "w+")
    f.write(result_file)
    f.close()

def get_kallsyms():
	global functions

	filename = "/proc/kallsyms"
	fd = open(filename, 'r')
	while True:
		line = fd.readline().strip()
		if not line:
			break
		line = line.split()
		if len(line) < 3:
			break
		if line[1] != 't' and line[1] != 'T':
			continue
		base = line[0]
		function_name = line[2]
		if len(line) > 3:
			function_name += " " + line[3]
		func_dict = {}
		func_dict[int(base,16)] = function_name
		functions.append(func_dict)

	functions.sort(key=lambda x: list(x.keys()))	
	fd.close()

def address_to_sym(address):
	global functions

	if not len(functions):
		get_kallsyms()

	start = 0
	end = len(functions) -1
	address = int(address,16)

	while start < end:
		mid = start + int((end - start) / 2)
		current_dict = functions[mid]
		base = list(current_dict.keys())[0]
		next_base = list(functions[mid + 1].keys())[0]
		if (address >= base) and (address < next_base):
			return current_dict[base]
			break
		elif address < base:
			end = mid
		else:
			start = mid + 1
	return None

def is_null(x):
	return x != ''

def free_alloc(alloc,ptr,ts):
	if not len(alloc):
		return None
	if ptr not in alloc:
		return None
	if ts >= alloc[ptr][-1]:
		alloc.pop(ptr)
		return True
	return None	

def get_unfree_count(alloc):
	unfree = {}
	if not len(alloc):
		print("unfree alloc error\n")
		return None
	for key,value in alloc.items():
		if (value[1] in unfree) and value[-1] > 0:
			info = unfree[value[1]]
			count = info[0] + 1
			info[0] = count
			info.append(value)
			unfree[value[1]] = info
		elif value[-1] > 0:
			info = []
			info.append(1)
			info.append(value)
			info.append(address_to_sym(value[1]))
			unfree[value[1]] = info
	res = ''
	for key,value in unfree.items():
		res += "[ip = {} function = {} count = {}] \n".format(key, value[2], value[0])
	return res

def get_unfree_alloc(perf_file):
	fd = open(perf_file,"r")
	alloc = {}
	start_ts = 0
	end_ts = 0
	while 1 :
		line = fd.readline()
		if not line :
			break
		if len(line) < 10 :
			continue
		line_list = line.strip().split(' ')
		line_list = list(filter(is_null,line_list))
		
		ts = None
		call_ip = None
		ptr = None
		free= None
		for item in line_list:
			item = item.strip()
			if item.find('.') != -1 and item[-1] == ':':
				ts = float(item[:-1])
				continue
			if item.find("call_site") != -1:
				call_ip = item[10:]
				continue
			if item.find('ptr=') != -1:
				ptr = item[4:]
				continue
			if item.find("alloc") != -1:
				free = 1
				continue
			if item.find("free") != -1:
				free = 2
		if not (ts or  call_ip or  ptr or free):
			continue
		if start_ts == 0:
			start_ts = ts
		end_ts = ts
		info = []
		info.append(ptr)	
		info.append(call_ip)	
		info.append(line_list[0])	
		info.append(ts)	
		if free == 1:
			alloc[ptr] = info
			continue
		if free == 2 :
			free_alloc(alloc,ptr,ts)	
	delta = end_ts - start_ts
	delta = delta * 0.1
	end_ts = end_ts - delta
	for key,item in alloc.items():
		item[-1] = end_ts - item[-1]

	return get_unfree_count(alloc)


def read_trace_pipe():
	global trace_event
	pipe_file = "/sys/kernel/debug/tracing/trace_pipe"
	fd = open(pipe_file, 'r')
	perf = open("/tmp/trace_event.txt", 'w+')
	kmem_trace_clear()

	while trace_event:
		buffers = fd.read(4096)
		perf.write(buffers)
	perf.close()
	kmem_trace_clear()

def kmem_write_sys(filename, ctx):
	fd = open(filename, 'r+')
	fd.write(ctx)

def kmem_write_enable(bytes_alloc):
	free = ["kfree", "kmem_cache_free"]
	allocs = ["kmalloc", "kmalloc_node", "kmem_cache_alloc", "kmem_cache_alloc_node"]
	debug_path = "/sys/kernel/debug/tracing/events/kmem"
	for event in free:
		slab_event = debug_path + os.sep + event
		enable = slab_event + os.sep + "enable"
		filters = slab_event + os.sep + "filter"
		filter_args = "ptr != 0"
		kmem_write_sys(filters, filter_args)
		kmem_write_sys(enable, "1")
	
	for event in allocs:
		slab_event = debug_path + os.sep + event
		enable = slab_event + os.sep + "enable"
		filters = slab_event + os.sep + "filter"
		filter_args = "bytes_alloc == " + str(bytes_alloc) + " "
		kmem_write_sys(filters, filter_args)
		kmem_write_sys(enable, "1")

def kmem_write_disable():
	free = ["kfree", "kmem_cache_free"]
	allocs = ["kmalloc", "kmalloc_node", "kmem_cache_alloc", "kmem_cache_alloc_node"]
	debug_path = "/sys/kernel/debug/tracing/events/kmem"
	
	for event in allocs:
		slab_event = debug_path + os.sep + event
		enable = slab_event + os.sep + "enable"
		kmem_write_sys(enable, "0")
	
	for event in free:
		slab_event = debug_path + os.sep + event
		enable = slab_event + os.sep + "enable"
		kmem_write_sys(enable, "0")

def kmem_trace_clear():
	filename = "/sys/kernel/debug/tracing/trace"
	kmem_write_sys(filename, "clear")
		
def kmem_trace_enable(bytes_alloc, delay):
	global trace_event
	kmem_write_enable(bytes_alloc)
	time.sleep(delay + 2)
	trace_event = None
	time.sleep(2)
	kmem_write_disable()
	kmem_trace_clear()

def read_thread(threadName, delay):
	read_trace_pipe()

def trace_event_start(object_size, timeout):
	thread.start_new_thread(read_thread, ("read_thread", 0))
	kmem_trace_enable(object_size, timeout)
	res = get_unfree_alloc("/tmp/trace_event.txt")
	os.remove("/tmp/trace_event.txt")
	return res

def get_slab_elem(filename):
	ctx = 0
	fd = open(filename, 'r')
	if not fd:
		return ctx
	ctx = fd.read().strip()
	return ctx

def slab_is_unreclaim(name):
	ret = 0
	slabname = name + os.sep + "reclaim_account"
	ret = get_slab_elem(slabname)
	return (int(ret) == 0)
	
def slab_get_objects(name):
	ret = 0
	slabname = name + os.sep + "objects"
	ret = get_slab_elem(slabname)
	ret = ret.split(' ')[0]
	return int(ret)

def slab_number_memleak(number, force):
	slab_dir = "/sys/kernel/slab"
	slab_link = {}
	max_objects = 0;
	max_slab = None;
	max_dict = {}
	for name in os.listdir(slab_dir):
		name_dir = slab_dir + os.sep + name
		if slab_is_unreclaim(name_dir) == False:
			continue

		slab_path = []
		linkname = name
		ret = os.path.islink(name_dir)
		if ret == True:
			linkname = os.readlink(name_dir).strip()

		objects = slab_get_objects(name_dir)
		if objects >= max_objects:
			max_objects = objects
			max_slab = linkname
		if linkname in slab_link:
			slab_path = slab_link[linkname]
			slab_path.append(name)
		else:
			filename = name_dir + os.sep + "object_size"
			size = get_slab_elem(filename)
			slab_path.append(int(size))
			slab_path.append(name)
			slab_link[linkname] = slab_path

			
	if max_objects > number or force:
		max_dict[max_slab] = slab_link[max_slab]

	return max_dict
			
def slab_total_memleak(rate):
	mem_total =	None 
	slab_unreclaim = None 

	fd = open("/proc/meminfo", 'r')
	while 1:
		line = fd.readline()
		if not line:
			break
		if mem_total and slab_unreclaim:
			break

		line = line.strip().split(' ')
		if line[0] == "MemTotal:":
			mem_total = int(line[-2])
			continue
		elif line[0] == "SUnreclaim:":
			slab_unreclaim = int(line[-2])
			continue
	if (slab_unreclaim * 100) > (mem_total * rate):
		return True
	else:
		return None	

def check_memleak(rate, number, size, timeout):
        ret = slab_total_memleak(rate)
        max_slab = slab_number_memleak(number, ret)
        print("ret {} slab {} size {}".format(ret, max_slab, size))
        if not (ret or len(max_slab) or size):
            return ''
        if size == 0:
                slabname = list(max_slab.keys())[0]
                object_size = max_slab[slabname][0]
                slabs = ''
                for value in max_slab[slabname][1:]:
                    slabs += value + " "
                print("slab name = {} size {}".format(slabs, object_size))
                size = object_size
        return trace_event_start(size, timeout)

if __name__ == "__main__":
    main()


