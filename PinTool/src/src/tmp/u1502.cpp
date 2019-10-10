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
	LogFile = fopen("./u1502.localSecret.txt", "a");
	return ( LogFile != NULL );
}

static VOID rc4_keyLogger( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);
	unsigned char * buffer = *(unsigned char **)(PIN_GetContextReg( ctxt, REG_ESP ) + 4);
	unsigned int len = *(unsigned int *)(PIN_GetContextReg( ctxt, REG_ESP ) + 8);
	
	static char callerStr[32];
	sprintf( callerStr, "RC4 key is: " );
	fwrite( callerStr, 12, 1, LogFile );
	for ( size_t i = 0; i < len; ++i )
	{
		sprintf ( callerStr, "%02x, ", buffer[i] );
		fwrite( callerStr, 4, 1, LogFile );
	}
	callerStr[0] = '\n';
	fwrite( callerStr, 1, 1, LogFile );
	fflush( LogFile );
	ReleaseLock(&fileLock);
}

static VOID log_recorder( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);
	unsigned char * buffer = (unsigned char *)PIN_GetContextReg( ctxt, REG_EDX );
	unsigned int len = PIN_GetContextReg( ctxt, REG_EBX );
	
	ADDRINT caller = PIN_GetContextReg( ctxt, REG_EBP );
	static char callerStr[32];
	sprintf( callerStr, "Caller: %08x\n", *(int *)(caller + 4) );
	fwrite( callerStr, 17, 1, LogFile );
	fwrite( buffer, len, 1, LogFile );
	fflush( LogFile );
	ReleaseLock(&fileLock);
}


static VOID local_decryptor( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);

	unsigned int len = PIN_GetContextReg( ctxt, REG_EAX );
	if ( len > 0x10000 || len < 10 )
	{
		ReleaseLock(&fileLock);
		return;
	}

	unsigned char * buffer = (unsigned char *)PIN_GetContextReg( ctxt, REG_EBX );
	if ( (unsigned int)buffer < 0x00401000 || (unsigned int)buffer > 0x10000000 )
	{
		ReleaseLock(&fileLock);
		return;
	}
	/*
	ADDRINT caller = PIN_GetContextReg( ctxt, REG_EBP );
	static char callerStr[32];
	sprintf( callerStr, "Caller: %08x\n", *(int *)(caller + 4) );
	fwrite( callerStr, 17, 1, LogFile );
	*/
	fwrite( buffer, len, 1, LogFile );
	fflush( LogFile );
	ReleaseLock(&fileLock);
}

// Pin calls this function every time a new instruction is encountered
static VOID Instruction(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);

	/*
	if ( pc == 0x4113fa ) // logging point
	{
		// Insert a call to printip before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)log_recorder, IARG_CONST_CONTEXT, IARG_END );
	}
	*/
	if ( pc == 0x40e11d ) // logging point
	{
		// Insert a call to printip before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)local_decryptor, IARG_CONST_CONTEXT, IARG_END );
	}
	/*
	if ( pc == 0x418470 ) // logging point
	{
		// Insert a call to printip before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)rc4_keyLogger, IARG_CONST_CONTEXT, IARG_END );
	}
	*/
}


// This function is called when the application exits
static VOID Fini(INT32 code, VOID *v)
{
	fclose(LogFile);
}


int u1502(int argc, char * argv[])
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
