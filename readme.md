
## Install DPFuzz

The fuzz testing environment can refer to the following script: [build.sh](https://github.com/aflgo/aflgo/blob/master/build.sh)

- python: `3.7`

```
pip install -r requirement.txt
```

- install DPFuzz

```shell
sudo make clean all && sudo make ;cd llvm_mode ;sudo make clean all && cd .. ;sudo bash -c 'echo core >/proc/sys/kernel/core_pattern'
```

## Run DPFuzz
1. lizard
```
lizard -l c -o=/lizard_<PROJECT>.txt
```
2. Collect code features
```
python script/py/prediction/collect_data_for_defect_prediction.py <PROJECT> <PUT_PATH> <LIZARD_PATH> <LLVM_PATH> <SAVE_PATH>
```
3. Defect prediction
```
# Pay attention to modifying the path in the code
python script/py/prediction/defectprediction.py
```
4. Compile program
   Refer to the script/testscript/mjs/mjs_pre.sh file
5. Run fuzz
   Refer to script/testscript/mjs/DPFuzz.sh file

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