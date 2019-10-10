#include <iostream>
#include <fstream>
#include <map>
#include <set>

#include "pin.H"
#include "kscope.h"

/*
 * The lock for I/O.
 */
static PIN_LOCK fileLock;

static FILE * LogFile;


static bool init_config()
{
	LogFile = fopen("./fg742.log.txt", "a");
	return ( LogFile != NULL );
}


static VOID printip( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);
	unsigned char * buffer = (unsigned char *)PIN_GetContextReg( ctxt, REG_EDX );
	unsigned int len = PIN_GetContextReg( ctxt, REG_EAX );
	fwrite( buffer, len - 1, 1, LogFile );
	fflush( LogFile );
	ReleaseLock(&fileLock);
}

// Pin calls this function every time a new instruction is encountered
static VOID Instruction(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);

	if ( pc == 0x420bc3 )
	{
		// Insert a call to printip before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_CONST_CONTEXT, IARG_END );
	}
}


// This function is called when the application exits
static VOID Fini(INT32 code, VOID *v)
{
	fclose(LogFile);
}


int fg742(int argc, char * argv[])
{
    // Initialize pin
    if ( PIN_Init(argc, argv) )
		return -1;

	if ( !init_config() )
	{
		puts("Init record file fails\n");
		return -1;
	}

	// Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    // PIN_AddFiniFunction(Fini, 0);
    
    // Callback functions to invoke before
    // Pin releases control of the application
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
