
using namespace std;

static FileManager Logger("./data/bbl.dll.log", "w");
static FileManager FpProf("./data/bblProfiling.log", "w");
static ConfigReader Config;
static FileManager FpCodePool("./data/bblInst.log", "w");
static Compressor BBLTracer;
const static size_t MAX_THREADS = 0x100;
static vector< map<ADDRINT, unsigned long long> > BBLProfDic(MAX_THREADS);
static map<ADDRINT, set<ADDRINT> > CallMap;

struct bbl
{
	ADDRINT addr;
	size_t thread;
};

static bbl B;
static FileManager DLLInfo("data/dll_info.log", "w");
static BOOL g_instrument_flag = false;
static BOOL g_record_flag = false;
static std::map<ADDRINT, std::string> funcNames;



static VOID PIN_FAST_ANALYSIS_CALL bblTrace(ADDRINT startAddr, UINT32 flag)
{
	if (flag == 1)
	{
		g_record_flag = true;
	}

	if (g_record_flag == true)
	{
		B.addr = startAddr;
		B.thread = PIN_ThreadId() & 0xFF;
		BBLProfDic[B.thread][startAddr] += 1;
		BBLTracer.save_data(&B, sizeof(bbl));
	}

	if (flag == 2)
	{
		g_record_flag = false;
	}
}
    
static VOID tracer(TRACE trace, VOID *v)
{
	//BBL_InsHead(bbl);
	//BBL_InsTail(bbl);
	UINT32 flag = 0;
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
		//for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		//{
		//	if (Config.get_codeStartAddr() == INS_Address(ins))
		//	{
		//		g_instrument_flag = true;
		//		flag = 1;
		//	}
		//	if (Config.get_codeEndAddr() == INS_Address(ins))
		//	{
		//		g_instrument_flag = false;
		//		flag = 2;
		//	}
		//}

		if (flag == 2) flag = 3;

		if (Config.get_codeStartAddr() >= INS_Address(BBL_InsHead(bbl)) && Config.get_codeStartAddr() <= INS_Address(BBL_InsTail(bbl)))
		{
			g_instrument_flag = true;
			flag = 1;
		}

		if (Config.get_codeEndAddr() >= INS_Address(BBL_InsHead(bbl)) && Config.get_codeEndAddr() <= INS_Address(BBL_InsTail(bbl)))
		{
			g_instrument_flag = false;
			flag = 2;
		}

		if (g_instrument_flag == true || flag == 2)
		{
			fprintf(FpCodePool.fp(), "----\r\n");
			for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				fprintf(FpCodePool.fp(), "%016llx|%s\r\n", INS_Address(ins), INS_Disassemble(ins).c_str());
			}
			fprintf(FpCodePool.fp(), "\r\n");

			// Arguments:
			// Ref: https://software.intel.com/sites/landingpage/pintool/docs/97971/Pin/html/group__INST__ARGS.html#ga089c27ca15e9ff139dd3a3f8a6f8451d
			// Ref: https://software.intel.com/sites/landingpage/pintool/docs/97971/Pin/html/group__INST__ARGS.html#ga5d3025eb005b7ea4745799f0ee1b86a6
			BBL_InsertCall(bbl, IPOINT_ANYWHERE, AFUNPTR(bblTrace), IARG_FAST_ANALYSIS_CALL,
				IARG_ADDRINT, BBL_Address(bbl),
				IARG_UINT32, flag,
				IARG_END);
		}

	}
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
	char arr[300] = { 0 };
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

// This function is called when the application exits
static VOID Fini(INT32 code, VOID *v)
{
	for ( size_t i = 0; i < MAX_THREADS; ++i )
	{
		if ( BBLProfDic[i].size() != 0 )
		{
			for ( map<ADDRINT, unsigned long long>::const_iterator it = BBLProfDic[i].begin(); it != BBLProfDic[i].end(); ++it )
			{
				fprintf( FpProf.fp(), "%016llx@%04d: %lld\r\n", it->first, i, it->second );
			}
		}
	}

	fprintf( Logger.fp(), "----FINI BBLTracer----\r\n");
	fflush(Logger.fp());

}

int main(int argc, char * argv[])
{
    // Initialize pin
    if ( PIN_Init(argc, argv) )
		return -1;
	PIN_InitSymbols();

	if ( !BBLTracer.set_trace_file("data/bblTracing.lzo") )
	{
		fprintf( Logger.fp(), "fail to set bblTracing lzo!!!\r\n");
		return -2;
	}
	fprintf( Logger.fp(), "----Injection----\r\n");

    // Register Instruction to be called to instrument instructions
	TRACE_AddInstrumentFunction(tracer, 0);

	// Register ImageLoad to be called when an image is loaded
	IMG_AddInstrumentFunction(ImageLoad, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
