# -*- coding: utf-8 -*-

import os
import json
import string
from collections import OrderedDict
import argparse
import re

if os.geteuid() != 0:
	print "This program must be run as root. Aborting."
	sys.exit(0)

def execCmd(cmd):
	r = os.popen(cmd)
	text = r.read()
	r.close()
	return text

def humConvert(value):
	units = ["B", "KB", "MB", "GB", "TB", "PB"]
	size = 1024.0
	for i in range(len(units)):
		if (value / size) < 1:
			return "%.2f%s/s" % (value, units[i])
		value = value / size

class latencyAnalysis:
	def __init__(self):
		self.delayStatDicts = {}
		self.delayDicts = {}
		self.summaryDicts = {}
		self.totalIosDicts = {}
		self.totalDelayDicts = {}
		self.diskIdxDicts = {}
		self.totalDiskCnt = 0
		self.threshold = 0
		self.componentDicts = OrderedDict([('os(block)',0),('os(driver)',1),\
						   ('disk',2),('os(complete)',3)])
		self.delayStatJsonStr = \
		'{	\
			"diskname":"","delays":[	\
			{"component":"os(block)","percent":"","max":0,"min":1000000000,"avg":0},\
			{"component":"os(driver)","percent":"","max":0,"min":1000000000,"avg":0},\
			{"component":"disk","percent":"","max":0,"min":1000000000,"avg":0},	\
			{"component":"os(complete)","percent":"","max":0,"min":1000000000,"avg":0}]\
		}'
		newDelayStatDict = json.loads("["+self.delayStatJsonStr + "]", object_pairs_hook=OrderedDict)
		self.delayStatDicts.setdefault('summary', newDelayStatDict)
		self.entryDictJsonStr = \
		'{	\
			"diskname":"",\
			"slow ios":[]	\
		}'
		newSummaryDict = json.loads("["+self.entryDictJsonStr + "]", object_pairs_hook=OrderedDict)
		self.summaryDicts.setdefault('summary', newSummaryDict)
		newDelayDict = json.loads("["+self.entryDictJsonStr + "]", object_pairs_hook=OrderedDict)
		self.delayDicts.setdefault('summary', newDelayDict)

	def __newDiskDict(self, disk):
		if self.totalDiskCnt != 0:
			newDelayStatDict = json.loads(self.delayStatJsonStr, object_pairs_hook=OrderedDict)
			self.delayStatDicts['summary'].append(newDelayStatDict)
			newSummaryDict = json.loads(self.entryDictJsonStr, object_pairs_hook=OrderedDict)
			self.summaryDicts['summary'].append(newSummaryDict)
			newDelayDict = json.loads(self.entryDictJsonStr, object_pairs_hook=OrderedDict)
			self.delayDicts['summary'].append(newDelayDict)
		self.delayStatDicts['summary'][self.totalDiskCnt]['diskname'] = disk
		self.summaryDicts['summary'][self.totalDiskCnt]['diskname'] = disk
		self.delayDicts['summary'][self.totalDiskCnt]['diskname'] = disk
		self.totalDelayDicts.setdefault(disk, 0)
		self.totalIosDicts.setdefault(disk, 0)
		self.diskIdxDicts.setdefault(disk, self.totalDiskCnt)
		self.totalDiskCnt += 1;

	def processLatencyDelays(self, sDict):
		diskIdxDicts = self.diskIdxDicts
		totalDelayDicts = self.totalDelayDicts
		componentDicts = self.componentDicts
		delayStatDicts = self.delayStatDicts
		delayDicts = self.delayDicts

		disk = sDict['diskname']
		del sDict['diskname']
		totalDelayDicts[disk] += sDict['totaldelay']
		diskIdx = diskIdxDicts[disk]
		delayDicts['summary'][diskIdx]['slow ios'].append(sDict)
		for component,idx in componentDicts.items():
			delay = sDict['delays'][idx]['delay']
			if delay > delayStatDicts['summary'][diskIdx]['delays'][idx]['max']:
				delayStatDicts['summary'][diskIdx]['delays'][idx]['max'] = delay
			if delay < delayStatDicts['summary'][diskIdx]['delays'][idx]['min']:
				delayStatDicts['summary'][diskIdx]['delays'][idx]['min'] = delay
			delayStatDicts['summary'][diskIdx]['delays'][idx]['avg'] += delay

	def processLatencySummary(self, sDict):
		diskIdxDicts = self.diskIdxDicts
		summaryDicts = self.summaryDicts

		disk = sDict['diskname']
		diskIdx = diskIdxDicts[disk]
		del sDict['diskname']
		listAbnormal=[i for i in sDict['abnormal'].split(' ') if i != ''];
		msDelay=int(listAbnormal[-2].strip('(').split(':')[0]) / 1000.000
		msTotalDelay=int(listAbnormal[-2].strip('(').split(':')[1]) / 1000.000
		sDict['abnormal']=listAbnormal[0]+' '+listAbnormal[1]+" ("+str(msDelay)+":"+str(msTotalDelay)+" ms)"
		summaryDicts['summary'][diskIdx]['slow ios'].append(sDict)

	def processOneLatencySeq(self, sDict):
		totalIosDicts = self.totalIosDicts

		disk = sDict['diskname']
		if disk not in totalIosDicts.keys():
			self.__newDiskDict(disk)

		totalIosDicts[disk] += 1
		if "abnormal" in sDict:
			self.processLatencySummary(sDict)
		else:
			self.processLatencyDelays(sDict)

	def latencyCalculate(self):
		diskIdxDicts = self.diskIdxDicts
		totalIosDicts = self.totalIosDicts
		totalDelayDicts = self.totalDelayDicts
		componentDicts = self.componentDicts
		delayStatDicts = self.delayStatDicts
		summaryDicts = self.summaryDicts
		delayDicts = self.delayDicts

		for disk, diskIdx in diskIdxDicts.items():
			totalIosDicts[disk] /= 2
			totalIos = totalIosDicts[disk]
			maxPercent = 0
			avgTotalDelay = totalDelayDicts[disk] / totalIos
			for component,idx in componentDicts.items():
				delayStatDicts['summary'][diskIdx]['delays'][idx]['avg'] /= totalIos
				avgDelay = delayStatDicts['summary'][diskIdx]['delays'][idx]['avg']
				#percent = avgDelay * 100.0 / avgTotalDelay
				percent = round((avgDelay * 100.0 / avgTotalDelay), 3)
				if percent > maxPercent:
					maxPercent = percent
				delayStatDicts['summary'][diskIdx]['delays'][idx]['percent'] = str(percent)+"%"

	def latencyPrint(self, threshold):
		diskIdxDicts = self.diskIdxDicts
		totalIosDicts = self.totalIosDicts
		summaryDicts = self.summaryDicts
		delayStatDicts = self.delayStatDicts
		componentDicts = self.componentDicts

		for disk, diskIdx in diskIdxDicts.items():
			totalIos = totalIosDicts[disk]
			summaryDicts['summary'][diskIdx]['slow ios']=\
				sorted(summaryDicts['summary'][diskIdx]['slow ios'],\
				       key=lambda e:float(re.split(':| ', e['abnormal'])[-2]),\
				       reverse=True)
			print("\n%d IOs of disk %s over %d ms, delay distribution:" %(totalIos, disk, threshold))
			for component,idx in componentDicts.items():
				percent = delayStatDicts['summary'][diskIdx]['delays'][idx]['percent']
				print("%-12s delay: %s" %(component, percent))

			end = totalIos if totalIos < 10 else 10
			print("The first %d IOs with the largest delay, more details:" % end)
			print("time".ljust(26)+"comm".ljust(20)+"pid".ljust(10)+"iotype".ljust(8)+\
			      "datalen".ljust(16)+"abnormal(delay:totaldelay)".ljust(40))

			for i in range(0,end):
				eDict=summaryDicts['summary'][diskIdx]['slow ios'][i]
				print(str(eDict["time"]).ljust(26)+eDict["comm"].ljust(20)+\
				      str(eDict["pid"]).ljust(10)+eDict["iotype"].ljust(8)+\
				      str(eDict["datalen"]).ljust(16)+eDict["abnormal"].ljust(40))

def latencyDataAnalysis(resultSeqFile, threshold):
	analysis = latencyAnalysis()
	f = open(resultSeqFile)
	for line in f.readlines():
		try:
			sDict = json.loads(line, object_pairs_hook=OrderedDict)
		except ValueError:
			continue
		analysis.processOneLatencySeq(sDict)
	f.close()
	if analysis.totalDiskCnt == 0:
		print("\n0 IOs over %d ms, everything is ok !^o^ ~" % int(threshold))
		return
	analysis.latencyCalculate()

	f = open(resultSeqFile.strip('.seq')+".stat", 'w+')
	f.write(json.dumps(analysis.delayStatDicts))
	f.close()

	f = open(resultSeqFile.strip('.seq'), 'w+')
	f.write(json.dumps(analysis.summaryDicts))
	f.close()

	f = open(resultSeqFile, 'w+')
	f.write(json.dumps(analysis.delayDicts))
	f.close()
	analysis.latencyPrint(int(threshold))
	print("more details see %s*" % resultSeqFile.strip('.seq'))

def main():
	examples = """e.g.
	./iosdiag_data_analysis.py -L -s -t 1000 -f ./result.log.seq	//Statistic IO delay diagnosis results
	./iosdiag_data_analysis.py -L -g -t 1000 -f ./result.log.seq	//Display IO delay diagnostic results graphically
	"""
	parser = argparse.ArgumentParser(
		description="Analyze IO diagnostic data.",
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog=examples)
	parser.add_argument('-L','--latency', action='store_true', help='Analyze IO delay diagnostic data.')
	parser.add_argument('-s','--stat', action='store_true', help='Statistic IO diagnosis results.')
	parser.add_argument('-g','--graph', action='store_true', help='Display IO diagnostic results graphically.')
	parser.add_argument('-t','--threshold', help='Specifies the threshold for the exception io.')
	parser.add_argument('-f','--file', help='Specify the target data file to analyze.')
	args = parser.parse_args()

	if args.latency:
		latencyDataAnalysis(args.file, 1000 if args.threshold == None else args.threshold)

if __name__ == "__main__":
	main()

