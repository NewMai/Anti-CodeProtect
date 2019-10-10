#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <set>
#include "pin.h"
#include "kscope.h"

static ConfigReader Config;
static FileManager FpCodePool("./data/insTracer.log", "w");
static FileManager Logger("./data/log.log", "w");
static FileManager DLLInfo("data/dll_info.log", "w");

static int g_instrument_flag = 0;
static int g_record_flag = 0;
static std::map<ADDRINT, std::string> insDict;
static std::map<ADDRINT, std::string> funcNames;
static std::string targetDllName = "";


static VOID print_ins(ADDRINT pc)
{
	fprintf(FpCodePool.fp(), "%016llx | %s\r\n", pc, insDict[pc].c_str());

}

// Pin calls this function every time a new instruction is encountered
static VOID instrumentor(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);
	ADDRINT target = 0;


	std::string insStr = INS_Disassemble(ins);
	insDict[pc] = insStr;
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_ins, IARG_INST_PTR, IARG_END);
	

}

static BOOL isASCII(std::string str)
{
	BOOL ret = true;
	char c = 0;
	for (int i = 0; i < str.length(); i++)
	{
		c = str.c_str()[i];
		if ((c < 33 || c > 126) && c != 0x20)
		{
			ret = false;
			break;
		}
	}
	return ret;
}
static std::string toASCII(std::string str)
{
	std::string ret = "";
	char arr[300] = {0};
	char c = 0;
	int len = 0;
	int tlen = 0;
	for (int i = 0; i < str.length(); i++)
	{
		c = str.c_str()[i];
		if ((33 > c || c > 126) && c != 0x20)
		{
			tlen = sprintf(arr + len, "0x%02X", c);
			len += tlen;
		}
		else
		{
			arr[len++] = c;
		}
	}
	ret = std::string(arr);
	return ret;
}

// Enumerate all the symbol in this image
static VOID MapAddrToName(IMG img)
{
	for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
	{
		std::string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
		ADDRINT addr = IMG_LowAddress(img) + SYM_Value(sym);

		if (isASCII(undFuncName))
		{
			funcNames[addr] = undFuncName;
		}
		else
		{
			undFuncName = toASCII(undFuncName);
			funcNames[addr] = undFuncName;
			fprintf(Logger.fp(), "Nor ascii function name: %s in address: 0x%016llx\r\n", undFuncName.c_str(), addr);
		}

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
