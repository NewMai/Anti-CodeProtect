#include "pin.H"
#include "kscope.h"

FILE * trace;

// Pin calls this function every time a new img is loaded
// It can instrument the image, but this example does not
// Note that imgs (including shared libraries) are loaded lazily

VOID hooker( const CONTEXT * const ctxt )
{
	fprintf(trace, "addr: %08x\n", PIN_GetContextReg( ctxt, REG_INST_PTR ) );
}

VOID ImageLoad(IMG img, VOID *v)
{
	if ( IMG_Name(img).find( "libeay" ) != string::npos || IMG_Name(img).find( "LIBEAY" ) != string::npos )
	{
		RTN monitoredRoutine = RTN_FindByName(img, "BN_mod_exp");
		if ( RTN_Valid(monitoredRoutine) )
		{
			RTN_Open(monitoredRoutine);
			RTN_InsertCall( monitoredRoutine, IPOINT_BEFORE, (AFUNPTR)hooker, IARG_CONST_CONTEXT, IARG_END );
	        
			// RTN_InsertCall(monitoredRoutine, IPOINT_AFTER, (AFUNPTR)CreateFileWafter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

			RTN_Close(monitoredRoutine);
		}
	}
}

// Pin calls this function every time a new img is unloaded
// You can't instrument an image that is about to be unloaded
VOID ImageUnload(IMG img, VOID *v)
{
	// fprintf(trace, "Unloading %s\n", IMG_Name(img).c_str());
}

// This function is called when the application exits
// It closes the output file.
VOID Fini(INT32 code, VOID *v)
{
    fclose(trace);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    PIN_ERROR("This tool prints a log of image load and unload events\n"
             + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int openssl_hook(int argc, char * argv[])
{
    trace = fopen("imageload.out", "w");

    // Initialize symbol processing
    PIN_InitSymbols();
    
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();
    
    // Register ImageLoad to be called when an image is loaded
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Register ImageUnload to be called when an image is unloaded
    IMG_AddUnloadFunction(ImageUnload, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
