#!/usr/bin/python2
# -*- coding: UTF-8 -*-

import sys,os
#import getopt
import argparse
import json
import linecache
import subprocess
from collections import OrderedDict

stack_trace = 0
eventpid = 0
lev_mask = 0
list_arg = 0
disable_arg = 0
enable_arg = 0
MAX_OUT_FILE = 512*1024*1024
ONE_FILE_MAX = 64*1024*1024
FILE_CACHE_SIZE = 4096

anal_file=''
traceoutf = "/sys/kernel/debug/tracing/trace"
event_pid_f = "/sys/kernel/debug/tracing/set_event_pid"
traceswfile = "/proc/sysak/schedtrace/pid"

#level low
tracefs1 = ("/sys/kernel/debug/tracing/events/sched/sched_wakeup/enable",
	"/sys/kernel/debug/tracing/events/sched/sched_migrate_task/enable",
	"/sys/kernel/debug/tracing/events/sched/sched_switch/enable",
	"/sys/kernel/debug/tracing/events/sched/sched_process_exit/enable")

#level middle
tracefs2 = ("/sys/kernel/debug/tracing/events/sched/sched_stat_iowait/enable",
	"/sys/kernel/debug/tracing/events/signal/signal_deliver/enable",
	"/sys/kernel/debug/tracing/events/signal/signal_generate/enable")

#level high
tracefs3 = ("/sys/kernel/debug/tracing/events/irq/irq_handler_entry/enable",
	 "/sys/kernel/debug/tracing/events/irq/irq_handler_exit/enable",
	 "/sys/kernel/debug/tracing/events/irq/softirq_entry/enable",
	 "/sys/kernel/debug/tracing/events/irq/softirq_exit/enable",
	 "/sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/enable",
	 "/sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/enable")

tracefiles = (tracefs1, tracefs2, tracefs3)

def usage():
	print '---usage---'
def do_enable(args):
	if len(args) == 0:
		usage()
def disable_args(strs):
	lenth = len(strs)
	if lenth == 0:
		print 'lenth == 0'
		return ['schedtrace_out.log', 512]
	elif lenth == 1:
		print 'lenth == 1'
		onearg = strs[0]
		if onearg.isdigit():
			if int(onearg) > 0:
				return ['schedtrace_out.log', int(onearg)]
			else:
				return []
		else:
			return [onearg, 512]
	elif lenth == 2:
		print 'lenth == 2'
		a0 = strs[0]
		a1 = strs[1]
		if a0.isdigit() and int(a0) > 0:
			return [a1, int(a0)]
		elif a1.isdigit() and int(a1) > 0:
			return [a0, int(a1)]
		else:
			return []
	else:
		print 'lenth == %d'% lenth
		return []
def parse_en_args(strs):
	maks = 0
	if not strs:
		mask = 1
	else:
		level_arg = strs[0]
		if level_arg == 'l':
			mask = 1
		elif level_arg == 'm':
			mask = 3
		elif level_arg == 's':
			mask = 7
		else:
			usage(sys.argv[0])
			sys.exit(" ::-e/--enable with invalid value")
	return mask
def check_essential_files(stack):
	if stack == 1 and not os.path.isfile(traceswfile):
		print 'WARN: no such file:%s' % traceswfile
		print ' --use root or check [schedtrace.ko] loaded yet?\n'
	if not os.path.isfile(traceoutf):
		print 'WARN: no such file:%s' % traceoutf
		print ' --use root or  check debugfs/tracefs mounted yet?--\n'
	if not os.path.isfile(event_pid_f):
		print 'WARN: no such file:%s' % event_pid_f
		print ' --use root or check debugfs/tracefs mounted yet?--\n'
	i = 0
	not_exist = 0
	while i < 3:
		traces = tracefiles[i]
		for tracef in traces:
			if not os.path.isfile(tracef):
				not_exist = not_exist + 1
		i = i + 1
	if not_exist > 1:
		print 'WARN: some files of /sys/kernel/debug/tracing/event/ not exist'
		print ' --use root or check debugfs/tracefs mounted yet?--'

	return

def disable_all_trace():
	i = 0
	while i < 3:
		traces = tracefiles[i]
		for tracef in traces:
			subprocess.call("echo 0 >"+tracef, shell=True)
		i = i + 1
	return

def parse_info(event, info, pid):
	if event == 'sched_switch':
		strs = info.split('==>')
		if pid in strs[0]:
			event = 'switch_out'
		elif pid in strs[1]:
			event = 'switch_in'
		else:
			print 'error:pid=%s, strs0=%s, strs1=%s' %(pid, strs[0], strs[1])
	return event

def raw_to_json(inf, outf):
	ifp = open(inf, "r")
	ofp = open(outf, "w")
	line1st = linecache.getline(inf, 1)
	target_pid = line1st.split('#')[-1].strip('\n')
	for line in ifp.readlines():
		if line[0] == '#':
			continue
		strs = line.split(':', 2)
		if len(strs) < 3:
			print 'line:\n   %s  not valide' % line
			continue
		dic = OrderedDict()
		dic['time'] = strs[0].split()[-1]
		info = strs[2].strip('\n')
		event = strs[1].split()[0]
		dic['event'] = parse_info(event, info, target_pid)
		dic['info'] = info
		#dic = {'time':float(time), 'event':event, 'info':info}  #dictory is disorder
		ofp.write(json.dumps(dic, sort_keys=False)+',\n')
	ifp.close()
	ofp.close()

def list_config():
	p = subprocess.Popen("cat "+event_pid_f, shell=True, stdout=subprocess.PIPE)
	p.wait()
	print '%s=%s' % (event_pid_f, p.stdout.readline().strip('\n'))
	i = 0
	while i < 3:
		traces = tracefiles[i]
		for tracef in traces:
			p = subprocess.Popen("cat "+tracef, shell=True, stdout=subprocess.PIPE)
			p.wait()
			print '%s=%s' % (tracef, p.stdout.readline().strip('\n'))
		i = i + 1
	return

def switch_fp(curr, t1, t2):
	if curr == t1:
		return t2
	elif curr == t2:
		return t1
	else:
		print 'Warn: switch_fp() curr not in t1 nor t2'
		return curr

def analysis_log(outfile, pid):
	switch_out = 0
	prv_time = 0.0000
	next_time = 0.0000
	wake_time = 0.0000
	prvtm_strs = ""
	nxttm_strs = ""
	prvstat = ""
	sched_swc = "sched_switch"
	sched_wkp = "sched_wakeup"
	splits = ""
	prev_pid = "prev_pid="+str(pid)
	next_pid = "next_pid="+str(pid)
	wkup_pid = "pid="+str(pid)
	fr = open(outfile, "r")
	
	for lines in fr.readlines():
		if (sched_swc not in lines and sched_wkp not in lines):
			continue
		if wkup_pid in lines and sched_wkp in lines:
			splits = lines.split(": sched_wakeup:")
			wake_time = float(splits[0].split()[-1])
		if prev_pid in lines:
			splits = lines.split("==>")
			splits1 = splits[0].split()
			#prv_events = splits1[-5].split(":")[0]
			prv_sta = splits1[-1]
			splits = lines.split(": sched_switch:")
			splits2 = splits[0].split()
			prvtm_strs = splits2[-1]
			try:
				prv_time = float(prvtm_strs);
			except:
				print 'prev:float excetpion'
				print '>>>%s' % lines
			else:
				#prvstat = splits[-7]
				switch_out = 1
		elif next_pid in lines and switch_out == 1:
			splits = lines.split(": sched_switch:")
			splits1 = splits[0].split()
			nxttm_strs = splits1[-1]
			try:
				next_time = float(nxttm_strs)
			except:
				print 'next:float excetpion'
				print '>>>%s' % lines
			else:
				total_delay = next_time - prv_time
				if total_delay > 0.009:
					if "=R" in prv_sta:
						print '%s was preempted %f sec\n%s ' % (pid, total_delay, lines)
						print '------------------------------------'
					if "=S" in prv_sta:
						s_delay = wake_time - prv_time
						w_delay = next_time - wake_time
						if wake_time > prv_time:
							print '%s sleep to wake:%f sec, wake to run:%f sec\n%s ' % (pid, s_delay, w_delay, lines)
						else:
							print '%s sleeped %f sec\n%s ' % (pid, total_delay, lines)
						print '------------------------------------'
						wake_time = 0.0000
					if "=D" in prv_sta:
						d_delay = wake_time - prv_time
						w_delay = next_time - wake_time
						if wake_time > prv_time:
							print '%s block to wake:%f sec, wake to run:%f sec\n%s ' % (pid, d_delay, w_delay, lines)
						else:
							print '%s blocked %f sec\n%s ' % (pid, total_delay, lines)
						print '------------------------------------'
						wake_time = 0.0000
			switch_out = 0

def record_traceinfo(outfile):
	tmp1 = outfile+'1'
	tmp2 = outfile+'2'
	trfp = open(traceoutf, 'r')
	t1fp = open(tmp1, 'w')
	t2fp = open(tmp2, 'w')
	total = 0
	count = 0
	tmpfp1 = t1fp
	line1st = linecache.getline(event_pid_f, 1)
	pid = line1st.split()[0]
	tmpfp1.write('#'+pid+'\n')
	try:
		while True:
			s = trfp.read(FILE_CACHE_SIZE)
			if s == '':
				break
			tmpfp1.write(s)
			count = count + FILE_CACHE_SIZE
			total = total + FILE_CACHE_SIZE
			if total > MAX_OUT_FILE:
				break;
			if count > ONE_FILE_MAX:
				tmpfp1 = switch_fp(tmpfp1, t1fp, t2fp)
				tmpfp1.seek(0, 0)
				tmpfp1.write('#'+pid+'\n')
				count = 0
	finally:
		tmpfp2 = switch_fp(tmpfp1, t1fp, t2fp)
		filename1 = tmpfp1.name
		filename2 = tmpfp2.name
		index1 = tmpfp1.tell()
		index2 = tmpfp2.tell()
		trfp.close()
		tmpfp1.close()
		tmpfp2.close()
		if index1 == 0 and index2 == 0:
			print '-- Notice: traced nothing --'
			os.remove(filename1)
			os.remove(filename2)
			return

		if index1 != 0:
			os.rename(filename1 , outfile)
			if index2 != 0:
				os.rename(filename2 , outfile+'.old')
			else:
				os.remove(filename2)
 		else:
			os.rename(filename2, outfile)
	print 'write total=%ld KB' % (total/1024)

def usage(app):
	print '=============='
	print 'Usage:'
	print '  -l/--list                 list the current trace config'
	print '  -p/--pid <targepid>       set the target pid we want to trace'
	print '  -s/--size <size>          set limit size of the output-file, MB'
	print '            size: limit the size of the output file, default 512MB'
	print '  -r/--read <outfile>       read the trace info to outfile'
	print '            stdout: will print the result to stdout console'
	print '  -j/--json <logfile>       trans the trace logfile to json'
	print '            logfile: the source file for json'
	print '  -a/--analy <logfile>      analysis trace logfile'
	print '            logfile: the source file for json'
	print '  -e/--enable <l|m|h>       enable sched trace with -p/--pid'
	print '            l: enable low-level trace' 
	print '            m: enable middle-level trace' 
	print '            h: enable high-level trace' 
	print '  -d/--disable <l|m|h>       disable sched trace with'
	print '            l: disable low-level trace' 
	print '            m: disable middle-level trace' 
	print '            h: disable high-level trace' 
	print '            p: disable trace target_pid' 
	print '=============='
	return

def cmd():
	parser = argparse.ArgumentParser()
	parser.add_argument("pid" , type=int, help='target pid')
	parser.add_argument("-l", '--list', dest="list", const=1, help='list configs', nargs='?')
	parser.add_argument("-S", '--stack', dest="stack", default=0, const=1, help='add stack-info for trace, if not sure just ignore', nargs='?')
	parser.add_argument("-s", '--size', dest="size", default=512, const=512, help='the size of trace log file(MB), default=512', nargs='?')
	parser.add_argument("-e", '--enable', dest="enable", help='enable schedtrace [level], default level=l, leaset info',choices=('l', 'm', 's'), const='l', nargs='?')
	parser.add_argument("-d", '--disable', dest="disable", const='schedtrace_out.log', help='disable schedtrace to [log file], default=schedtrace_out.log', nargs='?')
	parser.add_argument("-p", '--parse', type=str, dest="parse", help='parse the [log file], default=schedtrace_out.log', const='schedtrace_output.log', nargs='?')
	return parser.parse_args()

args = cmd()
d = args.__dict__

for key,value in d.iteritems():
	#print 'DEBUG:%s = %s'%(key,value)
	if key == 'stack' and value != None:
		stack_trace = value
		continue
	if key == 'size' and value != None:
		ONE_FILE_MAX = value
		continue
	if key == 'pid':
		eventpid = value
		continue
	if key == 'enable' and value != None:
		lev_mask = parse_en_args(value)
		enable_arg = 1
		continue
	if key == 'disable' and value != None:
		outfile = value
		disable_arg = 1
		continue
	if key == 'list' and value != None:
		check_essential_files(stack_trace)
		list_config()
		list_arg = 1
		continue
	if key == 'parse' and value != None:
		anal_file = value
		continue

	#if opt_name in ('-j', '--json'):
	#	raw_to_json(opt_value, opt_value+'.json')
	#	continue

if (enable_arg == 0 or disable_arg == 0) and list_arg == 0:
	useage()
	exit(0)
if enable_arg == 1:
	if eventpid == 0:
		usage(sys.argv[0])
		sys.exit("  ::target pid must be set first, use -p")
	if disable_level:
		sys.exit("  ::enable can't use with disable together, only -d or -e")
	check_essential_files(stack_trace)
	i = 0
	subprocess.call("echo "+str(eventpid)+" >"+event_pid_f, shell=True)
	if stack_trace == 1:
		subprocess.call("echo "+str(eventpid)+" >"+traceswfile, shell=True)
	while i < 3:
		if (lev_mask & (1 << i)):
			for tracefile in tracefiles[i]:
				subprocess.call("echo 1 >"+tracefile, shell=True)
		i = i + 1

elif disable_arg == 1:
	check_essential_files(stack_trace)
	if outfile == 'stdout':
		subprocess.call("cat "+traceoutf, shell=True)
	else:
		print 'write strace log to %s' % outfile
	disable_all_trace()	#should?
	record_traceinfo(outfile)
	subprocess.call("echo  >"+traceoutf, shell=True)
	if stack_trace == 1:
		subprocess.call("echo -1 >"+traceswfile, shell=True)

elif anal_file != '':
	if eventpid == 0:
		sys.exit("  ::analysis trace log must used with -p <pid>")
	else:
		analysis_log(anal_file, eventpid)
