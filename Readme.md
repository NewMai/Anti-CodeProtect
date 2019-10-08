
# Anti code protection project

Those scripts are used to convert BBLs from bblInst.log to IDA pro.
The bblInst.log is a tracer file generated by [Intel Pin Tools](https://software.intel.com/sites/landingpage/pintool/docs/97971/Pin/html/index.html).

# How to use those scripts for binary rewrite in IDA pro
NOTE: 
- Those python scripts are all writed in `python2.7` version.
- Your should check the error log file (error.log) for every step.

**step1:**

run `AssembleFuncForIDA.py` script in windows conmand line or linux bash shell:
```bash
python AssembleFuncForIDA.py > funcs.asm
```
This will generate a `funcs.asm` file. In this file, a list of psudo functions will be generated in assembly form.

**step2:**

run `addMachineCode.py` script in linux bash shell:
```bash
python addMachineCode.py
```
This script will generate corresponding machine code for each instruction in `func.asm` file and append the machine code to the end of each instruction. Finialy, a `funcsEx.asm` file will generate. In addition, you need to install pwntools on your linux machine before running this script.

**step3:**

run `funcRewritorForIDA.py` script in IDA pro:
```bash
Press ALT+F7 in IDA pro and select funcRewritorForIDA.py file to run
```
This script will create a new section in IDA pro and write the code (or instructions) from `funcsEx.asm` to this new section. Before running this script, your should open a whatever binary file in IDA pro.


# How to use those scripts for binary regeneration by using ML64.exe in Visual studio command line

**step1:**

run `AssembleFunc.py` script in windows with [keystone](http://www.keystone-engine.org/) installed to generate a assembly file: `funcsForML.asm`:
```bash
python AssembleFunc.py
```

**step2:**

Open the `visual studio comand line` for x64 environment and change the current directory to the location of this script file. Execute the following command:
```bash
ml64.exe /c funcsForML.asm
```
This step will genreates a object file :  `funcsForML.obj`


**step3:**

Open IDA pro and drap the object file into IDA pro.

