#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys,os
import getopt
import json
import linecache
import subprocess
from collections import OrderedDict

eventpid = 0
enable_level = 0
disable_level = 0
MAX_OUT_FILE = 512*1024*1024
ONE_FILE_MAX = 64*1024*1024
FILE_CACHE_SIZE = 4096

anal_file=''
traceoutf = "/sys/kernel/debug/tracing/trace"
pidfile = "/sys/kernel/debug/tracing/set_event_pid"
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

def check_essential_files():
	if not os.path.isfile(traceswfile):
		print 'WARN: no such file:%s' % traceswfile
		print ' --use root or check [schedtrace.ko] loaded yet?\n'
	if not os.path.isfile(traceoutf):
		print 'WARN: no such file:%s' % traceoutf
		print ' --use root or  check debugfs/tracefs mounted yet?--\n'
	if not os.path.isfile(pidfile):
		print 'WARN: no such file:%s' % pidfile
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
	p = subprocess.Popen("cat "+pidfile, shell=True, stdout=subprocess.PIPE)
	p.wait()
	print '%s=%s' % (pidfile, p.stdout.readline().strip('\n'))
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
	line1st = linecache.getline(pidfile, 1)
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
	print '            l: enabel low-level trace' 
	print '            m: enabel middle-level trace' 
	print '            h: enabel high-level trace' 
	print '  -d/--disable <l|m|h>       disable sched trace with'
	print '            l: disabel low-level trace' 
	print '            m: disabel middle-level trace' 
	print '            h: disabel high-level trace' 
	print '            p: disabel trace target_pid' 
	print '=============='
	return

if len(sys.argv) < 2:
	usage(sys.argv[0])
	sys.exit("invalide args")

try:
	opts,args = getopt.getopt(sys.argv[1:], 'hle:d:p:s:r:j:a:',['help','list', 'enable=','disable=','pid=','size=','read=','json=','analy'])
except getopt.GetoptError, e:
	sys.stderr.write("Error:[%s] %s\n" % (sys.argv[0].strip(".py"), e.msg))
	print 'Use -h/--help see useage!'
	sys.exit(1)
for opt_name,opt_value in opts:
	if opt_name in ('-h','--help'):
		usage(sys.argv[0])
		sys.exit()
	if opt_name in ('-l','--list'):
		check_essential_files()
		list_config()
		sys.exit()
	if opt_name in ('-p', '--pid'):
		eventpid = (int)(opt_value)
		continue
	if opt_name in ('-s', '--size'):
		ONE_FILE_MAX = 1024*1024*((int)(opt_value))
		continue
	if opt_name in ('-j', '--json'):
		raw_to_json(opt_value, opt_value+'.json')
		continue
	if opt_name in ('-a', '--analy'):
		anal_file = opt_value
		continue
	if opt_name in ('-r', '--read'):
		outfile = opt_value
		if outfile == 'stdout':
			subprocess.call("cat "+traceoutf, shell=True)
		else:
			print 'write strace log to %s' % outfile
			disable_all_trace()	#should?
			record_traceinfo(outfile)
			subprocess.call("echo  >"+traceoutf, shell=True)
			subprocess.call("echo -1 >"+traceswfile, shell=True)
		continue
	if opt_name in ('-e', '--enable'):
		enopt = opt_value
		if enopt == 'l':
			enable_level = 1
		elif enopt == 'm':
			enable_level = 3
		elif enopt == 'h':
			enable_level = 7
		else:
			usage(sys.argv[0])
			sys.exit(" ::-e/--enable with invalid value")
		continue
	if opt_name in ('-d', '--disable'):
		enopt = opt_value
		if enopt == 'l':
			disable_level = 7
		elif enopt == 'm':
			disable_level = 6
		elif enopt == 'h':
			disable_level = 4
		elif enopt == 'p':
			disable_level = 8
		else:
			usage(sys.argv[0])
			sys.exit(" ::-d/--disable with invalid value")
		continue
	else:
		usage(sys.argv[0])
		sys.exit("  ::undefined opt "+opt_name)

if enable_level:
	if eventpid == 0:
		usage(sys.argv[0])
		sys.exit("  ::target pid must be set first, use -p")
	if disable_level:
		sys.exit("  ::enabel can't use with disable together, only -d or -e")
	check_essential_files()
	i = 0
	subprocess.call("echo "+str(eventpid)+" >"+pidfile, shell=True)
	subprocess.call("echo "+str(eventpid)+" >"+traceswfile, shell=True)
	while i < 3:
		if (enable_level & (1 << i)):
			for tracefile in tracefiles[i]:
				subprocess.call("echo 1 >"+tracefile, shell=True)
		i = i + 1
elif disable_level:
	if enable_level:
		sys.exit("  ::enabel can't use with disable together, only -d or -e")
	check_essential_files()
	##this will be little complex,
	#but we usage a easy and ‘thick line’ way now times
	if disable_level == 8:
		if eventpid == 0:
			sys.exit("  ::disable trace pid must used with -p <pid>")
		else:
			disable_level = 7
			i = 0
			while i < 3:
				if disable_level & (1 << i):
					for tracefile in tracefiles[i]:
						subprocess.call("echo 0 >"+tracefile, shell=True)
				i = i + 1
			subprocess.call('echo >'+pidfile, shell=True)
			sys.exit()

	i = 0
	while i < 3:
		if disable_level & (1 << i):
			for tracefile in tracefiles[i]:
				subprocess.call("echo 0 >"+tracefile, shell=True)
		i = i + 1
	subprocess.call("echo -1 >"+traceswfile, shell=True)

elif anal_file != '':
	if eventpid == 0:
		sys.exit("  ::analysis trace log must used with -p <pid>")
	else:
		analysis_log(anal_file, eventpid)
