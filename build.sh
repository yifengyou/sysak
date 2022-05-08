#!/bin/bash

set -x

./configure --enable-target-all --kernel=4.19.91-23.4.an8.x86_64
make clean_middle
make

echo "All done![$?]"
