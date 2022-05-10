#!/bin/bash


WORKDIR=`pwd`
for mk in `find $(pwd)/source/tools/ -name Makefile -exec grep -l 'target :=' {} \; `;do
	echo ""
	echo ""
	echo ""
	mkfiledir=`dirname $mk`
	echo ${mkfiledir}
	cd $mkfiledir	
	ls -alh
	tree -L 2 -D
	cd ${WORKDIR}
done
