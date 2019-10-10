#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <set>
#include "pin.h"
#include "kscope.h"

static ConfigReader Config;
static FileManager FpCodePool("./data/dllTracer.log", "w");
static FileManager Logger("./data/log.log", "w");
static FileManager DLLInfo("data/dll_info.log", "w");

static int g_instrument_flag = 0;
static int g_record_flag = 0;
static std::map<ADDRINT, std::string> insDict;
static std::map<ADDRINT, std::string> funcNames;
static std::string targetDllName = "";


static VOID print_ins(ADDRINT pc)
{
	if (pc == Config.get_codeStartAddr())
	{
		g_record_flag = 1;
	}

	if (g_record_flag == 1)
	{
		fprintf(FpCodePool.fp(), "%016llx | %s\r\n", pc, insDict[pc].c_str());
	}
	
	if (pc == Config.get_codeEndAddr())
	{
		g_record_flag = 0;
	}
}
static VOID print_ins_ex(ADDRINT pc, ADDRINT target)
{
	std::string calleeName = "-";
	if (pc == Config.get_codeStartAddr())
	{
		g_record_flag = 1;
	}

	if (g_record_flag == 1)
	{
		std::map<ADDRINT, std::string>::iterator it = funcNames.find(target);
		if (it != funcNames.end())
		{
			calleeName = it->second;
		}

		fprintf(FpCodePool.fp(), "%016llx | %s | %s\r\n", pc, insDict[pc].c_str(), calleeName.c_str());
	}

	if (pc == Config.get_codeEndAddr())
	{
		g_record_flag = 0;
	}
}

// Pin calls this function every time a new instruction is encountered
static VOID instrumentor(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);
	ADDRINT target = 0;

	if (pc == Config.get_codeStartAddr())
	{
		g_instrument_flag = 1;
	}

	if (g_instrument_flag == 1 && (Config.in_dll_addr_range(pc) || Config.in_addr_range(pc)))
	{
		std::string insStr = INS_Disassemble(ins);
		insDict[pc] = insStr;
		//if (INS_IsCall(ins))
		if (INS_IsCall(ins) || std::string::npos != insStr.find("jmp"))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_ins_ex, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);
		}
		else
		{
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_ins, IARG_INST_PTR, IARG_END);
		}
	}

	if (pc == Config.get_codeEndAddr())
	{
		g_instrument_flag = 0;
	}
}

// Enumerate all the symbol in this image
static VOID MapAddrToName(IMG img)
{
	for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
	{
		std::string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
		ADDRINT addr = IMG_LowAddress(img) + SYM_Value(sym);
		funcNames[addr] = undFuncName;

		// Debug
		//fprintf(Logger.fp(), "Get function name: %s in address: 0x%016llx\r\n", undFuncName.c_str(), addr);
	}
}

static VOID ImageLoad(IMG img, VOID *v)
{
	char buf[100];
	int len = 0;
	static int i = 0;
	
	fprintf(DLLInfo.fp(), "Index: %02d\r\n", i++);
	fprintf(DLLInfo.fp(), "IMG_StartAddress = 0x%016llX\r\n", IMG_StartAddress(img));
	fprintf(DLLInfo.fp(), "IMG_Name = %s\r\n", IMG_Name(img).c_str());
	fprintf(DLLInfo.fp(), "IMG_Id = 0x%016llX\r\n", IMG_Id(img));
	fprintf(DLLInfo.fp(), "IMG_EntryAddress = 0x%016llX\r\n", IMG_EntryAddress(img));
	fprintf(DLLInfo.fp(), "IMG_Entry = 0x%016llX\r\n", IMG_Entry(img));
	fprintf(DLLInfo.fp(), "IMG_LoadOffset = 0x%016llX\r\n", IMG_LoadOffset(img));
	fprintf(DLLInfo.fp(), "IMG_LowAddress = 0x%016llX\r\n", IMG_LowAddress(img));
	fprintf(DLLInfo.fp(), "IMG_HighAddress = 0x%016llX\r\n", IMG_HighAddress(img));
	fprintf(DLLInfo.fp(), "\r\n");

	MapAddrToName(img);
	std::string imgName = IMG_Name(img);
	if (std::string::npos != imgName.find(targetDllName))
	{
		// Get the start address and end address of dll module
		Config.set_dllStartAddr(IMG_LowAddress(img));
		Config.set_dllEndAddr(IMG_HighAddress(img));

		fprintf(Logger.fp(), "Change config for module %s\r\n", IMG_Name(img).c_str());
		fprintf(Logger.fp(), "Set the start address to 0x%016llX\r\n", IMG_LowAddress(img));
		fprintf(Logger.fp(), "Set the end address to 0x%016llX\r\n", IMG_HighAddress(img));
	}
}

static VOID Fini(INT32 code, VOID *v)
{
	;
}

int main(int argc, char *argv[])
{
    if( PIN_Init(argc,argv) )
        return 1;
	PIN_InitSymbols();

	printf("argc = %d\n", argc);
	for (int i = 0; i < argc; i++)
	{
		printf("argv[%d] = %s\n", i, argv[i]);
	}

	//argv[0] = C:\PinTool\pin - 3.10 / ia32 / bin / pin.exe
	//argv[1] = -p64
	//argv[2] = C:\PinTool\pin - 3.10 / intel64 / bin / pin.exe
	//argv[3] = -t
	//argv[4] = C:\PinTool\pin - 3.10\dll\MyPinTool.dll
	//argv[5] = --
	//argv[6] = app\sm2_with_gmssl_sign.exe
	//argv[7] = libcrypto

	if (argc != 8)
	{
		fprintf(Logger.fp(), "Fail to set target dll name!\r\n");
		return -2;
	}
	targetDllName = std::string(argv[7]);
	fprintf(Logger.fp(), "Target dll name: %s\r\n", targetDllName.c_str());

    INS_AddInstrumentFunction(instrumentor, 0);
    PIN_AddFiniFunction(Fini, 0);

	// Register ImageLoad to be called when an image is loaded
	IMG_AddInstrumentFunction(ImageLoad, 0);

    // Start the program, never return
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
