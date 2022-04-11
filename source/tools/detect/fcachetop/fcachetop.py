#!/usr/bin/python2.7
# -*- coding: UTF-8 -*-

import os, sys, getopt, signal, threading
import argparse
from ctypes import c_int
from ctypes import c_size_t
from ctypes import c_ulong
from ctypes import c_ubyte
from ctypes import c_void_p
from ctypes import c_longlong
from ctypes import get_errno
from ctypes import CDLL
from ctypes import POINTER
from ctypes import cast
from mmap import MAP_SHARED
from mmap import PROT_READ
from mmap import PAGESIZE
from time import sleep

try:
	from ctypes import c_ssize_t
	c_off_t = c_ssize_t
except ImportError:
	is_64bits = sys.maxsize > 2 ** 32
	c_off_t = c_longlong if is_64bits else c_int

if os.geteuid() != 0:
	print "This program must be run as root. Aborting."
	sys.exit(1)

MAP_FAILED = c_ulong(-1).value
libc = CDLL(None)

_mmap = libc.mmap
_mmap.restype = c_void_p
_mmap.argtypes = c_void_p, c_size_t, c_int, c_int, c_off_t

_munmap = libc.munmap
_munmap.restype = c_void_p
_munmap.argtypes = c_void_p, c_size_t

_mincore = libc.mincore
_mincore.restypes = c_int
_mincore.argtypes = c_void_p, c_size_t, POINTER(c_ubyte)

hide_long_filepath = True

def execCmd(cmd):
	r = os.popen(cmd)
	text = r.read()
	r.close()
	return text

def hum_convert(value):
	units = ["B", "KB", "MB", "GB", "TB", "PB"]
	size = 1024.0
	for i in range(len(units)):
		if (value / size) < 1:
			return "%.2f%s" % (value, units[i])
		value = value / size

global_stop = False
def signal_exit_handler(signum, frame):
	global global_stop
	global_stop = True
	sys.exit(0)

class Filecachestat:
	def __init__(self, name, comm, pagecached, nr_page):
		self.filename = name
		self.comm = comm if comm is not None else '-'
		self.pagecached = pagecached
		self.nr_page = nr_page
		self.hit_percent = round(float(pagecached) * 100 / float(nr_page), 2)

	def dumpStat(self, verbose):
		len_filename = len(self.filename)
		filename = self.filename
		if len_filename > 48:
			if verbose == 0:
				filename_end = (self.filename)[(len_filename-30):len_filename]
				filename_start = (self.filename)[0:13]
				filename = "%s...%s" % (filename_start, filename_end)
			else:
				filename += ' '
		print "%s%s%-16d%-16s%s" \
			% (filename.ljust(48),\
			(str(self.pagecached)+'/'+hum_convert(self.pagecached*PAGESIZE)).ljust(24),\
			self.nr_page,\
			str(self.hit_percent)+"%",\
			self.comm)

def getCacheStat(filename, comm):
	if os.path.isfile(filename) and os.access(filename, os.R_OK):
		f = open(filename)
		size = os.fstat(f.fileno()).st_size
		if size == 0:
			f.close()
			return 0
		addr = _mmap(0, size, PROT_READ, MAP_SHARED, f.fileno(), 0)
		if addr == MAP_FAILED:
			#print "Failed to mmap %s (errno: %d)" % (filename, get_errno())
			f.close()
			return 0

		nr_pages = (size + PAGESIZE - 1) / PAGESIZE
		vec = (c_ubyte * nr_pages)()
		ret = _mincore(addr, size, cast(vec, POINTER(c_ubyte)))
		if ret != 0:
			#print "mincore failed: 0x%x, 0x%x: %d, filename: %s" % (addr, size, get_errno(), filename)
			_munmap(addr, size)
			f.close()
			return 0
		
		cached = list(vec).count(1)
		_munmap(addr, size)
		f.close()
		return Filecachestat(filename, comm, cached, nr_pages)
	else:
		#print "%s not existed" % filename
		return 0

def getLsofFiles():
	fDicts = {}
	pidList = os.listdir("/proc")
	#list the open files of the task
	for pid in pidList:
		if pid.isdigit() is False:
			continue
		piddir = "/proc/"+pid
		try:
			fdList = os.listdir(piddir+"/fd")
			for f in fdList:
				try:
					path = os.readlink(piddir+"/fd/"+f)
					if '/' not in path or ('/dev/' in path and '/shm/' not in path) or '/proc/' in path or '/sys/' in path:
						continue
					with open(piddir+"/comm") as f:
						comm = f.read().rstrip('\n')
					fDicts.setdefault(path, comm+':'+pid)
				except (IOError, EOFError) as e:
					continue
		except Exception:
			continue
	return fDicts

global_stat_list = []
def threadStatListUpdata(interval):
	global global_stop
	while global_stop != True:
		fDicts = getLsofFiles()
		#print(f_list)
		stat_list = filter(None, [getCacheStat(filename,comm) for filename,comm in fDicts.items()])
		#f_dict = getProcessFiles()
		#stat_list = filter(None, [getCacheStat(filename) for filename,existed in f_dict.items()])
		global global_stat_list
		global_stat_list = sorted(stat_list, key=lambda x:x.pagecached, reverse=True)
		if interval == 0:
			break
		sleep(interval - 1)

head_txt = "Name".ljust(48)+"Cached pages/size".ljust(24)+"Total pages".ljust(16)+"Hit percent".ljust(16)+"Comm:Pid"
def topFileCache(interval, top):
	if interval == 0:
		threadStatListUpdata(0)
	else:
		t = threading.Thread(target=threadStatListUpdata, args=(interval,))
		t.start()
	global global_stop
	while global_stop != True:
		topDisplay = 0
		total_cached = 0
		os.system("clear")
		print "The top%d Max cached open files:" %top
		print(head_txt)
		global global_stat_list
		for stat in global_stat_list:
			if topDisplay <= top:
				stat.dumpStat(verbose_long_filepath)
			total_cached += (stat.pagecached * PAGESIZE)
			topDisplay += 1
		if total_cached != 0:
			print "Total cached %s for all open files%s" %(hum_convert(total_cached),'(ctrl+c exit)' if interval else '')
		if interval == 0:
			break
		sleep(interval)
	sys.exit(0)

def main():
	examples = """e.g.
./fcachetop             Display the file pages cached of Top10\n\
./fcachetop -f /xxx/file\n\
                        Statistics the file pages cached for \'/xxx/file\'\n\
./fcachetop -i 2        Display the file pages cached per N seconds(CTRL+C exit)\n\
./fcachetop -T 30       Display the file pages cached of Top30\n"
	"""
	parser = argparse.ArgumentParser(
		description="Statistics the file page cached.",
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog=examples)
	parser.add_argument('-f','--file',\
			    help='Statistics the file pages cached from specified file.')
	parser.add_argument('-i','--interval', help='Display the file pages cached per N seconds(CTRL+C exit).')
	parser.add_argument('-T','--top', help='Display the file pages cached of TopN (default Top 10).')
	parser.add_argument('-v','--verbose', action='store_true',\
			    help='Display the full path of the file(By default, when the file path exceeds 48 characters, the full path of the file is hidden).')
	args = parser.parse_args()

	filename = args.file
	func_top = True if args.file is None else False
	top = int(args.top) if args.top else 10
	interval = int(args.interval) if args.interval is not None else 0

	global verbose_long_filepath
	verbose_long_filepath = args.verbose

	signal.signal(signal.SIGINT, signal_exit_handler)
	signal.signal(signal.SIGHUP, signal_exit_handler)
	signal.signal(signal.SIGTERM, signal_exit_handler)
	if func_top == True:
		os.system("clear")
		topFileCache(interval, top)
	elif filename is not None:
		print(head_txt)
		stat = getCacheStat(filename, None)
		assert stat != 0, "getCacheStat() failed"
		stat.dumpStat(verbose_long_filepath)

if __name__ == "__main__":
	main()
