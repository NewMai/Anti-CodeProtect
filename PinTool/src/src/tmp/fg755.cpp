#include <iostream>

#include "pin.H"
#include "kscope.h"

/*
 * The lock for I/O.
 */
static PIN_LOCK fileLock;

static FILE * LogFile;

struct BN
{
	unsigned char * buff;
	unsigned int len;
};
struct RSA
{
	unsigned char tmp[16];
	BN * n;
	BN * e;
};

static bool init_config()
{
	LogFile = fopen("./fg755.protocol.txt", "a");
	return ( LogFile != NULL );
}

static VOID rc4_keyLogger( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);
	unsigned char * buffer = *(unsigned char **)(PIN_GetContextReg( ctxt, REG_ESP ) + 4);
	unsigned int len = *(unsigned int *)(PIN_GetContextReg( ctxt, REG_ESP ) + 8);
	if ( len > 0x100 || len < 0x10 )
	{
		ReleaseLock(&fileLock);
		return;
	}

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


static VOID caller_recorder( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);

	ADDRINT caller = PIN_GetContextReg( ctxt, REG_ESP );
	static char callerStr[32];
	sprintf( callerStr, "Caller: %08x\n", *(int *)(caller) );
	fwrite( callerStr, 17, 1, LogFile );
	ReleaseLock(&fileLock);
}

static VOID log2_recorder( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);
	unsigned char * buffer = (unsigned char *)PIN_GetContextReg( ctxt, REG_EBP );
	unsigned int len = PIN_GetContextReg( ctxt, REG_EAX );
	if ( len > 0x10000 || len < 0x10 )
	{
		ReleaseLock(&fileLock);
		return;
	}

	char newline[] = "\n";
	fwrite( buffer, len, 1, LogFile );
	fwrite( newline, 1, 1, LogFile );

	fflush( LogFile );
	ReleaseLock(&fileLock);
}

static VOID log3_recorder( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);

	unsigned char * buffer = *(unsigned char **)(PIN_GetContextReg( ctxt, REG_ESP ));
	unsigned int len = PIN_GetContextReg( ctxt, REG_EAX );
	if ( len > 0x10000 || len < 0x10 )
	{
		ReleaseLock(&fileLock);
		return;
	}
	fwrite( buffer, len, 1, LogFile );
	fflush( LogFile );
	ReleaseLock(&fileLock);
}

static VOID log_recorder( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);
	unsigned char * buffer = (unsigned char *)PIN_GetContextReg( ctxt, REG_EDX );
	unsigned int len = PIN_GetContextReg( ctxt, REG_EBX );
	if ( len > 0x10000 || len < 0x10 )
	{
		ReleaseLock(&fileLock);
		return;
	}

	fwrite( buffer, len, 1, LogFile );
	fflush( LogFile );
	ReleaseLock(&fileLock);
}


static VOID local_decryptor( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);

	unsigned int len = 0;
	unsigned char * buffer = NULL;
	if ( PIN_GetContextReg( ctxt, REG_INST_PTR ) == 0x427534 ) // logging point
	{
		len = PIN_GetContextReg( ctxt, REG_EAX );
		buffer = (unsigned char *)PIN_GetContextReg( ctxt, REG_EBP );
	}
	if ( PIN_GetContextReg( ctxt, REG_INST_PTR ) == 0x4292b5 ) // logging point
	{
		len = PIN_GetContextReg( ctxt, REG_ESI );
		buffer = (unsigned char *)PIN_GetContextReg( ctxt, REG_EBP );
	}

	if ( len > 0x10000 || len < 0x10 )
	{
		ReleaseLock(&fileLock);
		return;
	}

	if ( (unsigned int)buffer < 0x00401000 || (unsigned int)buffer > 0x10000000 || buffer[0] == 0 )
	{
		ReleaseLock(&fileLock);
		return;
	}

	fwrite( buffer, len, 1, LogFile );
	fflush( LogFile );
	ReleaseLock(&fileLock);
}

static VOID send_hooker( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);

	ADDRINT esp = (ADDRINT)PIN_GetContextReg( ctxt, REG_ESP );

	unsigned int len = *(unsigned int *)(esp + 12);
	unsigned char * buffer = *(unsigned char **)(esp + 8);
	if ( len > 0x10000 || len < 0x10 )
	{
		ReleaseLock(&fileLock);
		return;
	}
	fprintf( LogFile, "send %04d bytes\n", len );
	for ( size_t i = 0; i < len; ++i )
		fprintf( LogFile, "%02x ", buffer[i] );
	fprintf( LogFile, "\n" );

	fflush( LogFile );
	ReleaseLock(&fileLock);
}

static VOID sendto_hooker( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);

	ADDRINT esp = (ADDRINT)PIN_GetContextReg( ctxt, REG_ESP );

	unsigned int len = *(unsigned int *)(esp + 12);
	unsigned char * buffer = *(unsigned char **)(esp + 8);
	if ( len > 0x10000 || len < 0x10 )
	{
		ReleaseLock(&fileLock);
		return;
	}
	fprintf( LogFile, "sendto %04d bytes\n", len );
	for ( size_t i = 0; i < len; ++i )
		fprintf( LogFile, "%02x ", buffer[i] );
	fprintf( LogFile, "\n" );

	fflush( LogFile );
	ReleaseLock(&fileLock);
}

static VOID recv_hooker( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);

	ADDRINT esp = (ADDRINT)PIN_GetContextReg( ctxt, REG_ESP );

	unsigned int len = *(unsigned int *)(esp + 12);
	unsigned char * buffer = *(unsigned char **)(esp + 8);
	if ( len > 0x10000 || len < 0x10 )
	{
		ReleaseLock(&fileLock);
		return;
	}
	fprintf( LogFile, "recv %04d bytes\n", len );
	for ( size_t i = 0; i < len; ++i )
		fprintf( LogFile, "%02x ", buffer[i] );
	fprintf( LogFile, "\n" );

	fflush( LogFile );
	ReleaseLock(&fileLock);
}

static VOID recvfrom_hooker( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);

	ADDRINT esp = (ADDRINT)PIN_GetContextReg( ctxt, REG_ESP );

	unsigned int len = *(unsigned int *)(esp + 12);
	unsigned char * buffer = *(unsigned char **)(esp + 8);
	if ( len > 0x10000 || len < 0x10 )
	{
		ReleaseLock(&fileLock);
		return;
	}
	fprintf( LogFile, "recvfrom %04d bytes\n", len );
	for ( size_t i = 0; i < len; ++i )
		fprintf( LogFile, "%02x ", buffer[i] );
	fprintf( LogFile, "\n" );

	fflush( LogFile );
	ReleaseLock(&fileLock);
}

static VOID rc4_hooker( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);

	ADDRINT esp = (ADDRINT)PIN_GetContextReg( ctxt, REG_ESP );

	unsigned int len = *(unsigned int *)(esp + 8);
	unsigned char * buffer = *(unsigned char **)(esp + 4);
	if ( len > 0x10000 || len < 0x10 )
	{
		ReleaseLock(&fileLock);
		return;
	}
	fprintf( LogFile, "rc4 input %04d bytes\n", len );
	for ( size_t i = 0; i < len; ++i )
		fprintf( LogFile, "%02x ", buffer[i] );
	fprintf( LogFile, "\n" );

	fflush( LogFile );
	ReleaseLock(&fileLock);
}

static VOID rsa_encrypt_hooker( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);

	ADDRINT esp = (ADDRINT)PIN_GetContextReg( ctxt, REG_ESP );

	unsigned int inLen = *(unsigned int *)(esp + 4);
	unsigned int outLen = PIN_GetContextReg( ctxt, REG_EAX );
	unsigned char * inBuffer = *(unsigned char **)(esp + 8);
	unsigned char * outBuffer = *(unsigned char **)(esp + 12);
	RSA * r = *(RSA **)(esp + 16);

	fprintf( LogFile, "rsa encrypt input %04d bytes\n", inLen );
	for ( size_t i = 0; i < inLen; ++i )
		fprintf( LogFile, "%02x ", inBuffer[i] );
	fprintf( LogFile, "\n" );
	fprintf( LogFile, "rsa encrypt output %04d bytes\n", outLen );
	for ( size_t i = 0; i < outLen; ++i )
		fprintf( LogFile, "%02x ", outBuffer[i] );
	fprintf( LogFile, "\n" );
	fprintf( LogFile, "rsa N\n" );
	for ( size_t i = 0; i < (r->n->len) * 4; ++i )
		fprintf( LogFile, "%02x ", r->n->buff[i] );
	fprintf( LogFile, "\n" );
	fprintf( LogFile, "rsa e\n" );
	for ( size_t i = 0; i < (r->e->len) * 4; ++i )
		fprintf( LogFile, "%02x ", r->e->buff[i] );
	fprintf( LogFile, "\n" );


	fflush( LogFile );
	ReleaseLock(&fileLock);
}

static VOID rsa_decrypt_hooker( const CONTEXT * const ctxt )
{
	GetLock(&fileLock, 1);

	ADDRINT esp = (ADDRINT)PIN_GetContextReg( ctxt, REG_ESP );

	unsigned int inLen = *(unsigned int *)(esp + 4);
	unsigned int outLen = PIN_GetContextReg( ctxt, REG_EAX );
	unsigned char * inBuffer = *(unsigned char **)(esp + 8);
	unsigned char * outBuffer = *(unsigned char **)(esp + 12);
	RSA * r = *(RSA **)(esp + 16);

	fprintf( LogFile, "rsa decrypt input %04d bytes\n", inLen );
	for ( size_t i = 0; i < inLen; ++i )
		fprintf( LogFile, "%02x ", inBuffer[i] );
	fprintf( LogFile, "\n" );
	fprintf( LogFile, "rsa decrypt output %04d bytes\n", outLen );
	for ( size_t i = 0; i < outLen; ++i )
		fprintf( LogFile, "%02x ", outBuffer[i] );
	fprintf( LogFile, "\n" );
	fprintf( LogFile, "rsa N\n" );
	for ( size_t i = 0; i < (r->n->len) * 4; ++i )
		fprintf( LogFile, "%02x ", r->n->buff[i] );
	fprintf( LogFile, "\n" );
	fprintf( LogFile, "rsa e\n" );
	for ( size_t i = 0; i < (r->e->len) * 4; ++i )
		fprintf( LogFile, "%02x ", r->e->buff[i] );
	fprintf( LogFile, "\n" );


	fflush( LogFile );
	ReleaseLock(&fileLock);
}

// Pin calls this function every time a new instruction is encountered
static VOID Instruction(INS ins, VOID *v)
{
	ADDRINT pc = INS_Address (ins);
	/*
	if ( pc == 0x423A70 || pc == 0x425220 || pc == 0x429FF0 ) // logging point
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)caller_recorder, IARG_CONST_CONTEXT, IARG_END );

	if ( pc == 0x425295 ) // logging point
	{
		// Insert a call to printip before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)log2_recorder, IARG_CONST_CONTEXT, IARG_END );
	}
	if ( pc == 0x425295 ) // logging point
	{
		// Insert a call to printip before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)log3_recorder, IARG_CONST_CONTEXT, IARG_END );
	}

	if ( pc == 0x42a440 ) // logging point
	{
		// Insert a call to printip before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)log_recorder, IARG_CONST_CONTEXT, IARG_END );
	}

	if ( pc == 0x4292b5 || pc == 0x427534 ) // logging point
	{
		// Insert a call to printip before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)local_decryptor, IARG_CONST_CONTEXT, IARG_END );
	}
	

	if ( pc == 0x475d50 ) // logging point
	{
		// Insert a call to printip before every instruction, and pass it the IP
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)rc4_keyLogger, IARG_CONST_CONTEXT, IARG_END );
	}
	*/

	if ( pc == 0x71b62ec2 ) // logging point
	{
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)send_hooker, IARG_CONST_CONTEXT, IARG_END );
	}
	if ( pc == 0x71b11120 ) // logging point
	{
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recv_hooker, IARG_CONST_CONTEXT, IARG_END );
	}
	if ( pc == 0x71b63d14 ) // logging point
	{
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)sendto_hooker, IARG_CONST_CONTEXT, IARG_END );
	}
	if ( pc == 0x71b1309a ) // logging point
	{
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)recvfrom_hooker, IARG_CONST_CONTEXT, IARG_END );
	}
	if ( pc == 0x475de0 ) // logging point
	{
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)rc4_hooker, IARG_CONST_CONTEXT, IARG_END );
	}
	if ( pc == 0x4e75f2 ) // logging point
	{
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)rsa_encrypt_hooker, IARG_CONST_CONTEXT, IARG_END );
	}
	if ( pc == 0x4e7682 ) // logging point
	{
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)rsa_decrypt_hooker, IARG_CONST_CONTEXT, IARG_END );
	}
}


// This function is called when the application exits
static VOID Fini(INT32 code, VOID *v)
{
	fclose(LogFile);
}


int fg755(int argc, char * argv[])
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
