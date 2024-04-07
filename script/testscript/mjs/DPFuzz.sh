#!/bin/bash
# Repeatedly test the project
source /home/a/fuzz/DPfuzz/script/allenv.sh

pjname=DPFuzz
flag=1
times=1
while(( $flag<=$times ))
do
    $DPFuzz/afl-fuzz -m 3G -z /home/a/DPFuzztmp -i $mjs/obj-temp/fuzz_in -o $mjs/obj-temp/$pjname/fuzz_out$flag $mjs/obj-temp/mjs-bin -f @@
	echo $flag
	let "flag++"
done