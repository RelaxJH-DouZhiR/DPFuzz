#!/bin/bash
# Preprocessing script

source /home/a/fuzz/DPfuzz/script/allenv.sh
#
rm -rf $mjs/obj-temp
mkdir $mjs/obj-temp
mkdir $mjs/obj-temp/fuzz_in
mkdir $mjs/obj-temp/DPFuzz

if [ ! -d "$HOME/DPFuzztmp" ]; then
    mkdir $HOME/DPFuzztmp
fi

if [ -d "$HOME/DPFuzztmp" ]; then
    rm -rf $HOME/DPFuzztmp
    mkdir $HOME/DPFuzztmp
fi

cd $HOME/DPFuzztmp
touch instrumentation.txt
touch flag.txt
echo "0" > $HOME/DPFuzztmp/flag.txt

cp $mjs/mjs/tests/*.js $mjs/obj-temp/fuzz_in

cd $mjs/obj-temp
$CC -DMJS_MAIN $mjs/mjs.c -ldl -g -o $mjs/obj-temp/mjs-bin

$py38 $fuzzfile/script/py/merge.py mjs /home/a/DPFuzztmp /home/a/fuzz/DPfuzz/script/py/prediction/prediction_result/randomforest_fuzz/mjs.csv