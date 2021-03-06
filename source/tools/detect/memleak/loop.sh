#!/bin/bash

while :
do
insmod ../kernel/mem.ko
./main -t slab -i300 -n all
sleep 10
./main -t page -i500
sleep 10
./main -t slab -i200 -n kmalloc-64
sleep 10
rmmod mem
insmod ../kernel/mem.ko

./main -t slab -i100 -n kmalloc-192
sleep 10
./main -t page -i500
sleep 10
./main -i10 -n kmalloc-32
rmmod mem
insmod ../kernel/mem.ko
done
