#include <stdio.h>
#include "pin.H"
#include "kscope.h"
#include "minilzo.h"

static unsigned int CodeStartAddr = 0x00401000;
static unsigned int CodeEndAddr = 0x00800000;

static size_t TraceData[WRITE_BUF_MAX_LEN];
static size_t FuncCounter = 0;

Compressor compressor;

static VOID call_probe( ADDRINT callTarget )
{
	TraceData[FuncCounter++] = callTarget;
	TraceData[FuncCounter++] = PIN_ThreadId() & 0xFFFF;
	if ( WRITE_BUF_MAX_LEN == FuncCounter )
	{
		compressor.save_data( reinterpret_cast<unsigned char *>(TraceData), 4 * FuncCounter );
		FuncCounter = 0;
	}
}


// Pin calls this function every time a new instruction is encountered
static VOID Instruction(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);

	if ( pc > CodeStartAddr && pc < CodeEndAddr )
	{
		if ( INS_IsCall(ins) )
		{
			INS_InsertCall
			(
				ins, IPOINT_TAKEN_BRANCH, AFUNPTR(call_probe), 
				IARG_BRANCH_TARGET_ADDR, IARG_END
			);
		}
	}
}


// This function is called when the application exits
static VOID Fini(INT32 code, VOID *v)
{
	compressor.save_data( reinterpret_cast<unsigned char *>(TraceData), 4 * FuncCounter );
	puts("\n--FiNi--\n");
}


static bool init()
{
	if ( init_code_section( CodeStartAddr, CodeEndAddr ) == false )
	{
		puts("init codeSection failed\n");
		return false;
	}

	return compressor.set_trace_file("data/funcTracing.bin");
}

int func_tracer(int argc, char * argv[])
{
    // Initialize pin
    if ( PIN_Init(argc, argv) )
		return -1;

	if ( !init() )
		return -1;

	/*
	 * Step 1: initialize the LZO library
	 */
    if ( lzo_init() != LZO_E_OK )
    {
        printf("internal error - lzo_init() failed !!!\n");
        printf("(this usually indicates a compiler bug - try recompiling\nwithout optimizations, and enable '-DLZO_DEBUG' for diagnostics)\n");
        return -1;
    }
	
	// Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);


    // Register Fini to be called when the application exits
    PIN_AddFiniFunction( Fini, 0 );

	// let the entry point value to be zero.
	TraceData[FuncCounter++] = 0;
	TraceData[FuncCounter++] = PIN_ThreadId() & 0xFFFF;
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
