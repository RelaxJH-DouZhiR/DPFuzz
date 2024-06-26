
## Install DPFuzz

The fuzz testing environment can refer to the following script: [build.sh](https://github.com/aflgo/aflgo/blob/master/build.sh)

- python: `3.8.19`

```
pip install -r requirement.txt
```

- Install DPFuzz

```shell
# Warning! Please modify the file path according to the situation.
# Create a temporary file to store intermediate files. If the directory does not exist, DPFuzz will prompt during instrumentation and testing.
# Please execute the following command after each PC startup: sudo bash -c 'echo core >/proc/sys/kernel/core_pattern'

if [ ! -d "$HOME/fuzzloctmp" ]; then
    mkdir $HOME/fuzzloctmp
fi

if [ -d "$HOME/fuzzloctmp" ]; then
    rm -rf $HOME/fuzzloctmp
    mkdir $HOME/fuzzloctmp
fi

cd $HOME/fuzzloctmp
touch instrumentation.txt
touch flag.txt
echo "0" > $HOME/fuzzloctmp/flag.txt
sudo make clean all && sudo make ;cd llvm_mode ;sudo make clean all && cd .. ;sudo bash -c 'echo core >/proc/sys/kernel/core_pattern'
```

## Run DPFuzz
1. lizard

`<PROJECT>` : the name of the project.

```shell
# Warning! Please modify the file path according to the situation.
lizard -l c -o=/lizard_<PROJECT>.txt
# such as:
# lizard -l c -o=/lizard_mjs.txt
```
2. Collect code features

`<PROJECT>` : the name of the project.

`<PUT_PATH>` : The folder path of the project under testing.

`<LIZARD_PATH>` : the folder path of the lizard output file.

`<LLVM_PATH>` : the folder path of the LLVM lib.

`<SAVE_PATH>` : the folder path of the save file.
```shell
# Warning! Please modify the file path according to the situation.
# Please ensure that the Python version can run clang, such as 3.7. It may be necessary to modify the file='libclang-11.so 'in the cindex of clang to file='libclang.so'
python script/py/prediction/collect_data_for_defect_prediction.py <PROJECT> <PUT_PATH> <LIZARD_PATH> <LLVM_PATH> <SAVE_PATH>
# such as:
# python /home/a/fuzz/DPfuzz/script/py/prediction/collect_data_for_defect_prediction.py mjs /home/a/fuzz/DPfuzz/dataset/mjs /home/a/fuzz/DPfuzz/script/py/prediction/lizard_file /home/a/build/llvm_tools/build-llvm/llvm/lib /home/a/fuzz/DPfuzz/script/py/prediction/PUT_features
```
3. Defect prediction

- You need to modify the code in the adapt library to collect code features:
   - Modify the 'predict_estimator' return method in the 'adapt' to 'predict_proba' to obtain defect propensity, which was originally 'predict', in line 631.
```shell
# Pay attention to modifying the path in the code.
python script/py/prediction/defectprediction.py
```
4. Compile program
   Refer to the script/testscript/mjs/mjs_pre.sh file
5. Run fuzz
   Refer to script/testscript/mjs/DPFuzz.sh file

- Demonstration video: [DemoVideo](https://github.com/RelaxJH-DouZhiR/DPFuzz/blob/main/NativeDPFuzzDemo.mp4)

## Use VM
The virtual machine is a very convenient way to use DPFuzz, requires VMware 17.5.1.
1. Download DPFuzz4VM: [DPFuzz4VM](https://onedrive.live.com/?cid=CCBA0C915DA6D466&id=CCBA0C915DA6D466%21s247ba9954af24cea9146e15eaa928f2c&parId=root&o=OneUp)
    - User name : `richard`
    - Password : `zrcl991201`
2. The virtual machine demonstration video: [VMDemoVideo](https://github.com/RelaxJH-DouZhiR/DPFuzz/blob/main/VMDPFuzzDemo.mp4)
3. The virtual machine demonstration script:
```shell
# Step 1
cd /home/richard/my_toolbox/DPFuzz/DPFuzz
make clean all && make
cd /home/richard/my_toolbox/DPFuzz/script/testscript/mjs
bash mjs_pre.sh #password : zrcl991201
cd /home/richard/my_toolbox/DPFuzz/DPFuzz/llvm_mode
make clean all && cd ..
# Step 2
cd /home/richard/my_toolbox/DPFuzz/dataset/mjs
lizard -l c -o=/home/richard/my_toolbox/DPFuzz/script/py/prediction/lizard_file/lizard_mjs_output.txt
# Step 3
conda activate py38
python /home/richard/my_toolbox/DPFuzz/script/py/prediction/collect_data_for_defect_prediction.py mjs /home/richard/my_toolbox/DPFuzz/dataset/mjs /home/richard/my_toolbox/DPFuzz/script/py/prediction/lizard_file /home/richard/anaconda3/envs/py38/lib/python3.8/site-packages/clang/native /home/richard/my_toolbox/DPFuzz/script/py/prediction/PUT_features
# Step 4
cd /home/richard/my_toolbox/DPFuzz/script/py/prediction
python defectprediction.py
# Step 5
cd /home/richard/my_toolbox/DPFuzz/script/testscript/mjs
bash mjs_pre.sh
bash DPFuzz.sh
```

## Install dataset
- **NASA NASADefectDataset**
```
git clone https://github.com/klainfo/NASADefectDataset.git
```
- binutils
```
git clone git://sourceware.org/git/binutils-gdb.git binutils
cd binutils; git checkout a9d9a10 ; git describe --tags a9d9a10
```
- giflib
```
git clone https://git.code.sf.net/p/giflib/code giflib
cd giflib; git checkout 72e31ff ; git describe --tags 72e31ff
```
- jasper
```
git clone https://github.com/mdadams/jasper.git jasper
cd jasper; git checkout 142245b ; git describe --tags 142245b
```
- libming
```
git clone https://github.com/libming/libming.git libming
cd libming; git checkout b72cc2f ; git describe --tags b72cc2f
```
- libxml2
```
git clone https://gitlab.gnome.org/GNOME/libxml2.git libxml2
cd libxml2; git checkout ef709ce2 ; git describe --tags ef709ce2
```
- lrzip
```
git clone https://github.com/ckolivas/lrzip.git lrzip
cd lrzip; git checkout 9de7ccb ; git describe --tags 9de7ccb
```
- mjs
```
git clone https://github.com/cesanta/mjs.git mjs
cd mjs; git checkout d6c06a6 ; git describe --tags d6c06a6
```
- libtiff
```
git clone https://github.com/vadz/libtiff.git libtiff
cd libtiff; git checkout 36511f8 ; git describe --tags 36511f8
```
- libpng
```
git clone https://github.com/glennrp/libpng.git libpng
cd libpng; git checkout b78804f ; git describe --tags b78804f
```
- tcpdump
```
git clone https://github.com/the-tcpdump-group/tcpdump.git tcpdump
cd tcpdump; git checkout f16dc4f ; git describe --tags f16dc4f

cd /dataset/lib/libpcap-1.7.2
sudo apt-get install flex
sudo apt-get install bison
./configure
sudo make install
```
- harfbuzz
```
git clone https://github.com/harfbuzz/harfbuzz.git harfbuzz
cd harfbuzz; git checkout 03538e8 ; git describe --tags 03538e8
```
- libjpeg
```
http://www.ijg.org/files/
```
- jhead
```
https://www.sentex.ca/~mwandel/jhead/
```
- mupdf
```
git clone https://github.com/ArtifexSoftware/mupdf.git mupdf
cd mupdf; git checkout ea5799e ; git describe --tags ea5799e
```
