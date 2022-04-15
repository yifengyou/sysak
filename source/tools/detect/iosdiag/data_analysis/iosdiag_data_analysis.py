# -*- coding: utf-8 -*-

import os
import json
import string
from collections import OrderedDict
import argparse
import re

if os.geteuid() != 0:
	print("This program must be run as root. Aborting.")
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
		self.totalDiskCnt += 1

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
		listAbnormal=[i for i in sDict['abnormal'].split(' ') if i != '']
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
			totalIosDicts[disk] = int(totalIosDicts[disk] / 2)
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
			print("%-26s%-20s%-10s%-8s%-16s%s" % \
				('time', 'comm', 'pid', 'iotype', 'datalen', 'abnormal(delay:totaldelay)'))

			for i in range(0,end):
				eDict=summaryDicts['summary'][diskIdx]['slow ios'][i]
				print("%-26s%-20s%-10s%-12s%-12s%s" % \
					(str(eDict["time"]), \
					eDict["comm"], \
					str(eDict["pid"]),\
					eDict["iotype"],\
					str(eDict["datalen"]),\
					eDict["abnormal"]))

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

class hangAnalysis():
	def __init__(self):
		self.statDicts = {}
		self.summaryDicts = {}
		self.detailDicts = {}
		self.totalIosDicts = {}
		self.diskIdxDicts = {}
		self.totalDiskCnt = 0
		self.statJsonStr = \
	'{	\
	"diskname":"",\
	"hung ios":[	\
		{"component":"os","count":0,"percent":"","max":0,"min":1000000000,"avg":0},\
		{"component":"disk","count":0,"percent":"","max":0,"min":1000000000,"avg":0}]	\
	}'
		newStatDict = json.loads("["+self.statJsonStr + "]", object_pairs_hook=OrderedDict)
		self.statDicts.setdefault('summary', newStatDict)
		self.entryDictJsonStr = \
		'{	\
			"diskname":"",\
			"hung ios":[]	\
		}'
		newSummaryDict = json.loads("["+self.entryDictJsonStr + "]", object_pairs_hook=OrderedDict)
		self.summaryDicts.setdefault('summary', newSummaryDict)
		newDetailDicts = json.loads("["+self.entryDictJsonStr + "]", object_pairs_hook=OrderedDict)
		self.detailDicts.setdefault('summary', newDetailDicts)

	def __newDiskDict(self, disk):
		if self.totalDiskCnt != 0:
			newStatDicts = json.loads(self.statJsonStr, object_pairs_hook=OrderedDict)
			self.statDicts['summary'].append(newStatDicts)
			newSummaryDict = json.loads(self.entryDictJsonStr, object_pairs_hook=OrderedDict)
			self.summaryDicts['summary'].append(newSummaryDict)
			newDetailDicts = json.loads(self.entryDictJsonStr, object_pairs_hook=OrderedDict)
			self.detailDicts['summary'].append(newDetailDicts)
		self.statDicts['summary'][self.totalDiskCnt]['diskname'] = disk
		self.summaryDicts['summary'][self.totalDiskCnt]['diskname'] = disk
		self.detailDicts['summary'][self.totalDiskCnt]['diskname'] = disk
		self.totalIosDicts.setdefault(disk, 0)
		self.diskIdxDicts.setdefault(disk, self.totalDiskCnt)
		self.totalDiskCnt += 1

	def processOneHangSeq(self, sDict):
		statDicts = self.statDicts
		totalIosDicts = self.totalIosDicts
		diskIdxDicts = self.diskIdxDicts
		summaryDicts = self.summaryDicts
		detailDicts = self.detailDicts
		components = ['OS', 'Disk']

		disk = sDict['diskname']
		del sDict['diskname']
		if disk not in totalIosDicts.keys():
			self.__newDiskDict(disk)

		diskIdx = diskIdxDicts[disk]
		if "abnormal" in str(sDict):
			totalIosDicts[disk] += 1
			statDict = statDicts['summary'][diskIdx]
			abnormalList = sDict['abnormal'].split()
			hungComponentIdx = components.index(abnormalList[0].split('(')[0])
			hungDelay = long(abnormalList[-2])
			statDict['hung ios'][hungComponentIdx]['count'] += 1
			maxHungDelay = statDict['hung ios'][hungComponentIdx]['max']
			minHungDelay = statDict['hung ios'][hungComponentIdx]['min']
			if hungDelay > maxHungDelay:
				statDict['hung ios'][hungComponentIdx]['max'] = hungDelay
			if hungDelay < minHungDelay:
				statDict['hung ios'][hungComponentIdx]['min'] = hungDelay
			statDict['hung ios'][hungComponentIdx]['avg'] += hungDelay
			abnormalList[-2] = str(round(hungDelay / 1000000.000, 3))
			abnormalList[-1] = 's'
			sDict['abnormal'] = ''.join(str(e)+' ' for e in abnormalList).strip()
			summaryDicts['summary'][diskIdx]['hung ios'].append(sDict)
		else:
			detailDicts['summary'][diskIdx]['hung ios'].append(sDict)
		
	def hangStatCalculate(self):
		statDicts = self.statDicts
		totalIosDicts = self.totalIosDicts
		diskIdxDicts = self.diskIdxDicts
		components = {'OS':0, 'Disk':1}

		for disk, diskIdx in diskIdxDicts.items():
			for component, idx in components.items():
				if statDicts['summary'][diskIdx]['hung ios'][idx]['count'] != 0:
					avgDelay = statDicts['summary'][diskIdx]['hung ios'][idx]['avg']
					avgDelay /= (statDicts['summary'][diskIdx]['hung ios'][idx]['count'])
					statDicts['summary'][diskIdx]['hung ios'][idx]['avg'] = avgDelay
					percent = statDicts['summary'][diskIdx]['hung ios'][idx]['count'] * 100.0 / totalIosDicts[disk]
				else:
					statDicts['summary'][diskIdx]['hung ios'][idx]['min'] = 0
					percent = 0
				statDicts['summary'][diskIdx]['hung ios'][idx]['percent'] = str(round(percent, 3)) + "%"
				statDicts['summary'][diskIdx]['hung ios'][idx]['component'] = component

	def hangPrint(self):
		diskIdxDicts = self.diskIdxDicts
		totalIosDicts = self.totalIosDicts
		summaryDicts = self.summaryDicts
		statDicts = self.statDicts
		components = {'OS':0, 'Disk':1}

		for disk, diskIdx in diskIdxDicts.items():
			totalIos = totalIosDicts[disk]
			summaryDicts['summary'][diskIdx]['hung ios']=\
				sorted(summaryDicts['summary'][diskIdx]['hung ios'],\
				       key=lambda e:float(e['abnormal'].split()[-2]),\
				       reverse=True)
			print("\n%d IOs hung of disk %s, IO hung distribution:" %(totalIos, disk))
			for component,idx in components.items():
				percent = statDicts['summary'][diskIdx]['hung ios'][idx]['percent']
				print("%-12s delay: %s" %(component, percent))

			end = totalIos if totalIos < 10 else 10
			print("The first %d IOs with the largest delay, more details:" % end)
			print("%-26s%-20s%-10s%-12s%-12s%-12s%-50s%s" % \
				('time', 'comm', 'pid', 'iotype', 'sector', 'datalen', 'abnormal', 'file'))

			for i in range(0,end):
				eDict=summaryDicts['summary'][diskIdx]['hung ios'][i]
				print("%-26s%-20s%-10s%-12s%-12s%-12s%-50s%s" % \
					(str(eDict["time"]), \
					eDict["comm"] if len(eDict["comm"]) else '-', \
					str(eDict["pid"]) if eDict["pid"] != -1 else '-',\
					eDict["iotype"],\
					str(eDict["sector"]),\
					str(eDict["datalen"]),\
					eDict["abnormal"], \
					eDict["file"] if len(eDict["file"]) else '-'))

def hangDataAnalysis(resultSeqFile, threshold):
	analysis = hangAnalysis()
	f = open(resultSeqFile)
	for line in f.readlines():
		try:
			sDict = json.loads(line, object_pairs_hook=OrderedDict)
		except ValueError:
			continue
		analysis.processOneHangSeq(sDict)
	f.close()

	if analysis.totalDiskCnt == 0:
		print("\nnot IO hang, everything is ok !^o^ ~")
		return
	analysis.hangStatCalculate()

	f = open(resultSeqFile.strip('.seq')+".stat", 'w+')
	f.write(json.dumps(analysis.statDicts))
	f.close()

	f = open(resultSeqFile.strip('.seq'), 'w+')
	f.write(json.dumps(analysis.summaryDicts))
	f.close()

	f = open(resultSeqFile, 'w+')
	f.write(json.dumps(analysis.detailDicts))
	f.close()
	analysis.hangPrint()
	print("more details see %s*" % resultSeqFile.strip('.seq'))

def main():
	examples = """e.g.
	./iosdiag_data_analysis.py -L -s -t 1000 -f ./result.log.seq	//Statistic IO delay diagnosis results
	./iosdiag_data_analysis.py -H -s -t 2000 -f ./result.log.seq	//Statistic IO hang diagnosis results
	"""
	parser = argparse.ArgumentParser(
		description="Analyze IO diagnostic data.",
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog=examples)
	parser.add_argument('-L','--latency', action='store_true', help='Analyze IO delay diagnostic data.')
	parser.add_argument('-H','--hangdetect', action='store_true', help='Analyze IO hang diagnostic data.')
	parser.add_argument('-s','--stat', action='store_true', help='Statistic IO diagnosis results.')
	parser.add_argument('-t','--threshold', help='Specifies the threshold for the exception io.')
	parser.add_argument('-f','--file', help='Specify the target data file to analyze.')
	args = parser.parse_args()

	if args.latency:
		latencyDataAnalysis(args.file, 1000 if args.threshold == None else args.threshold)
	if args.hangdetect:
		hangDataAnalysis(args.file, 5000 if args.threshold == None else args.threshold)

if __name__ == "__main__":
	main()

