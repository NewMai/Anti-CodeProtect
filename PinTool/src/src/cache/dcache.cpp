#include "pin.H"

#include <iostream>
#include <fstream>
#include <time.h>
#include <stack>
#include <map>
#include <algorithm>

#include "cache.H"
#include "pin_profile.H"
#include "kscope.h"

using namespace std;

//* ===================================================================== */
//* Commandline Switches */
//* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool", "o", "data/dcache.out", "specify dcache file name");
KNOB<BOOL>   KnobTrackLoads(KNOB_MODE_WRITEONCE,    "pintool",
    "l", "0", "track individual loads -- increases profiling time");
KNOB<BOOL>   KnobTrackStores(KNOB_MODE_WRITEONCE,   "pintool",
    "s", "0", "track individual stores -- increases profiling time");
KNOB<UINT32> KnobThresholdHit(KNOB_MODE_WRITEONCE , "pintool",
    "rh", "100", "only report memops with hit count above threshold");
KNOB<UINT32> KnobThresholdMiss(KNOB_MODE_WRITEONCE, "pintool",
    "rm","100", "only report memops with miss count above threshold");
KNOB<BOOL>   KnobIgnoreStores(KNOB_MODE_WRITEONCE,  "pintool", 
    "ns", "0", "ignore all stores");
KNOB<BOOL>   KnobIgnoreSize(KNOB_MODE_WRITEONCE,    "pintool", 
    "z", "0", "ignore size of all references (default size is 4 bytes)");
KNOB<UINT32> KnobCacheSize(KNOB_MODE_WRITEONCE,     "pintool",
    "c","16", "cache size in kilobytes");
KNOB<UINT32> KnobLineSize(KNOB_MODE_WRITEONCE,      "pintool",
    "b","64", "cache block size in bytes");
KNOB<UINT32> KnobAssociativity(KNOB_MODE_WRITEONCE, "pintool",
    "a","4", "cache associativity (1 for direct mapped)");

//* ===================================================================== */

static INT32 Usage()
{
    cerr << "This tool represents a cache simulator.\n";
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

static long BeginTime = 0;
static long EndTime = 0;
static ADDRINT LowBound		= 0x00400000;   // text段下界
static ADDRINT UpBound		= 0x01000000;   // text段上界

typedef  COUNTER_ARRAY<UINT64, COUNTER_NUM> COUNTER_HIT_MISS;

static const unsigned int MAX_CLOCK = 0x100000;

// 每16ms内Miss Cache的次数
static unsigned int interval_miss_nums[MAX_CLOCK] = {0};

//记录每16ms内执行过哪些访问了cache的函数  
static std::map<ADDRINT, bool> interval_funcs[MAX_CLOCK];

//函数调用栈
static std::stack<ADDRINT> func_stack;    

//记录执行过的操作内存的指令总数
static unsigned long insts_count = 0;


const unsigned int MAX_GROUP_NUM = 1000000;
const unsigned int GROUP_SIZE_BITS = 10;

//将指令按照1024为单位分作一组，记录每1024条指令里命中/缺失的次数
static unsigned int GroupMisses[MAX_GROUP_NUM] = {0};

//记录每1024条指令内执行过哪些访问了cache的函数 
static std::map<ADDRINT, bool> GroupFuncs[MAX_GROUP_NUM];

//将指令按照1024为单位分作一组，记录每1024条指令里访问cache的次数
//static unsigned int GroupHitsImage[MAX_GROUP_NUM] = {0};

static const int MAX_INS_NUM = 0x4000000;
static unsigned int instMissNum[MAX_INS_NUM] = {0};
static std::map<ADDRINT, ADDRINT> insFuncMap;                 //指令及其所属函数的对应关系
//static map<ADDRINT, int> instMissNum;                       //记录执行的执行次数




// holds the counters with misses and hits
// conceptually this is an array indexed by instruction address
COMPRESSOR_COUNTER<ADDRINT, UINT32, COUNTER_HIT_MISS> profile;

// ===================================================================== */
static bool is_in_range(ADDRINT pc)
{
	return (pc >= LowBound && pc <= UpBound);
}




static VOID statistics(BOOL dl1Hit, ADDRINT pc, UINT32 instId)
{
	// insts_count++;	

	int counter = dl1Hit ? 1: 0;
    profile[instId][counter]++;

	// rst.push_back(Time_cache(clock(), counter));
	// clock_t tmp_time = clock() >> 4;
	// interval_miss_nums[tmp_time] += counter;
	// interval_funcs[tmp_time][func_stack.top()] = true;

	// GroupMisses[insts_count >> GROUP_SIZE_BITS] += counter;
	// GroupFuncs[insts_count >> GROUP_SIZE_BITS][func_stack.top()] = true;
	// GroupHitsImage[insts_count >> GROUP_SIZE_BITS]++;

	instMissNum[pc - LowBound] += counter;
}



static VOID LoadMulti(ADDRINT addr, UINT32 size, UINT32 instId, ADDRINT pc)
{
    // first level D-cache
    const BOOL dl1Hit = dl1->Access(addr, size, CACHE_BASE::ACCESS_TYPE_LOAD);

    statistics(dl1Hit, pc, instId);
}



VOID StoreMulti(ADDRINT addr, UINT32 size, UINT32 instId, ADDRINT pc)
{
    // first level D-cache
    const BOOL dl1Hit = dl1->Access(addr, size, CACHE_BASE::ACCESS_TYPE_STORE);

    statistics(dl1Hit, pc, instId);
}



VOID LoadSingle(ADDRINT addr, UINT32 instId, ADDRINT pc)
{
    // @todo we may access several cache lines for 
    // first level D-cache
    const BOOL dl1Hit = dl1->AccessSingleLine(addr, CACHE_BASE::ACCESS_TYPE_LOAD);

    statistics(dl1Hit, pc, instId);
}


VOID StoreSingle(ADDRINT addr, UINT32 instId, ADDRINT pc)
{
    // @todo we may access several cache lines for 
    // first level D-cache
    const BOOL dl1Hit = dl1->AccessSingleLine(addr, CACHE_BASE::ACCESS_TYPE_STORE);

    statistics(dl1Hit, pc, instId);
}



VOID LoadMultiFast(ADDRINT addr, UINT32 size)
{
    dl1->Access(addr, size, CACHE_BASE::ACCESS_TYPE_LOAD);
}



VOID StoreMultiFast(ADDRINT addr, UINT32 size)
{
    dl1->Access(addr, size, CACHE_BASE::ACCESS_TYPE_STORE);
}



VOID LoadSingleFast(ADDRINT addr)
{
    dl1->AccessSingleLine(addr, CACHE_BASE::ACCESS_TYPE_LOAD);
}



VOID StoreSingleFast(ADDRINT addr)
{
    dl1->AccessSingleLine(addr, CACHE_BASE::ACCESS_TYPE_STORE);    
}


static VOID do_call(ADDRINT target_pc)
{
	func_stack.push(target_pc);
}

static VOID do_ret(VOID)
{
	if (!func_stack.empty())
	{
		func_stack.pop();
		if ( func_stack.empty() )
			func_stack.push(0);
	}
}

static VOID Instruction(INS ins, VOID * v)
{
	ADDRINT pc = INS_Address(ins);
	//printf("%08X: %s\n", pc, INS_Disassemble(ins).c_str());

	
	if (is_in_range(pc))
	{
		if (INS_IsMemoryRead(ins))
		{
			//INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) counting, IARG_END);

			// map sparse INS addresses to dense IDs
			const ADDRINT iaddr = INS_Address(ins);
			const UINT32 instId = profile.Map(iaddr);

			const UINT32 size = INS_MemoryReadSize(ins);
			const BOOL   single = (size <= 4) | KnobIgnoreSize;
	                
			if( KnobTrackLoads )
			{
				if( single )
				{
					INS_InsertPredicatedCall
					(
						ins, IPOINT_BEFORE, (AFUNPTR) LoadSingle,
						IARG_MEMORYREAD_EA,
						IARG_UINT32, instId,
						IARG_INST_PTR,
						IARG_END
					);
				}
				else
				{
					INS_InsertPredicatedCall
					(
						ins, IPOINT_BEFORE,  (AFUNPTR) LoadMulti,
						IARG_MEMORYREAD_EA,
						IARG_MEMORYREAD_SIZE,
						IARG_UINT32, instId,
						IARG_INST_PTR,
						IARG_END
					);
				}
	                
			}
			else
			{
				if( single )
				{
					INS_InsertPredicatedCall
					(
						ins, IPOINT_BEFORE,  (AFUNPTR) LoadSingleFast,
						IARG_MEMORYREAD_EA,
						IARG_END
					);
				}
				else
				{
					INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE,  (AFUNPTR) LoadMultiFast,
						IARG_MEMORYREAD_EA,
						IARG_MEMORYREAD_SIZE,
						IARG_END);
				}
			}
		}

		if ( INS_IsMemoryWrite(ins) && !KnobIgnoreStores )
		{
			//INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) counting, IARG_END);

			// map sparse INS addresses to dense IDs
			const ADDRINT iaddr = INS_Address(ins);
			const UINT32 instId = profile.Map(iaddr);
	            
			const UINT32 size = INS_MemoryWriteSize(ins);
			const BOOL   single = (size <= 4) | KnobIgnoreSize;
	                
			if( KnobTrackStores )
			{
				if( single )
				{
					INS_InsertPredicatedCall
					(
						ins, IPOINT_BEFORE,  (AFUNPTR) StoreSingle,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, instId,
						IARG_INST_PTR,
						IARG_END
					);
				}
				else
				{
					INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE,  (AFUNPTR) StoreMulti,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYWRITE_SIZE,
						IARG_UINT32, instId,
						IARG_INST_PTR,
						IARG_END);
				}
	                
			}
			else
			{
				if( single )
				{
					INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE,  (AFUNPTR) StoreSingleFast,
						IARG_MEMORYWRITE_EA,
						IARG_END);
	                        
				}
				else
				{
					INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE,  (AFUNPTR) StoreMultiFast,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYWRITE_SIZE,
						IARG_END);
				}
			}
	            
		}
	}

	if ( INS_IsCall(ins) )
	{	
		INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)do_call, IARG_BRANCH_TARGET_ADDR, IARG_END);
	}
	else if ( INS_IsRet(ins))
	{	
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)do_ret, IARG_END);
	}

	insFuncMap[pc] = func_stack.top();
}



static VOID write_time_cache(char * filename)
{
	FILE* f_time_cache = fopen(filename, "w");

	//std::map<clock_t, unsigned int> tmp;
	//cout << rst.size() << endl;
	//for (std::vector<Time_cache>::iterator iter = rst.begin();
	//	iter != rst.end();
	//	iter++)
	//{
	//	//cout << iter->cur_time << " " << iter->cache_rst << endl;
	//	if (iter->cache_rst == COUNTER_HIT)
	//	{
	//		clock_t tmp_time = iter->cur_time / 10;
	//		if (tmp.find(tmp_time) == tmp.end())
	//			tmp[tmp_time] = 0;
	//		tmp[tmp_time] ++;
	//	}		
	//}
	//for (std::map<clock_t, unsigned int>::iterator iter = tmp.begin();
	//	iter != tmp.end();
	//	iter++)
	//{
	//	//cout << iter->first << " " << iter->second << endl;
	//	fprintf(f_time_cache, "%d: %u\n", iter->first, iter->second);
	//}
	unsigned int start = 0, end = 0;
	for (unsigned int i = 0; i < MAX_CLOCK; i++)
	{
		if (interval_miss_nums[i] != 0)
		{
			start = i;
			break;
		}
	}
	for (unsigned int i = MAX_CLOCK - 1; i > 0; i--)
	{
		//printf("%u\n", i);
		if (interval_miss_nums[i] != 0)
		{
			end = i;
			break;
		}
	}

	//printf("%08x, %08x\n", start, end);
	for (unsigned int i = start; i < end; i++)
	{
		fprintf(f_time_cache, "%u:%u\n", i, interval_miss_nums[i]);
	}

	//printf("end\n");
	fclose(f_time_cache);
}

static VOID write_time_func(char* filename)
{
	FILE* f_time_func = fopen(filename, "w");
	unsigned int start = 0, end = 0;

	for (unsigned int i = 0; i < MAX_CLOCK; i++)
	{
		if (interval_funcs[i].size() != 0)
		{
			start = i;
			break;
		}
	}
	for (unsigned int i = MAX_CLOCK - 1; i >= 0; i--)
	{
		if (interval_funcs[i].size() != 0)
		{
			end = i;
			break;
		}
	}

	for (unsigned int i = start; i < end; i++)
	{
		fprintf(f_time_func, "%u:", i);
		for (std::map<ADDRINT, bool>::iterator iter = interval_funcs[i].begin();
			iter != interval_funcs[i].end();
			iter++)
		{
			if (is_in_range(iter->first))
				fprintf(f_time_func, "%08x|", iter->first);
			else
				break;
		}
		fprintf(f_time_func, "\n");
	}

	fclose(f_time_func);
}

static VOID write_ins_cache( char* file1, char* file2 )
{
	FILE* f_ins_cache = fopen(file1, "w");
	FILE* f_group_func = fopen(file2, "w");
	long long start = 0, end = 0;

	//fprintf(f_ins_cache, "%lld\n", insts_count);

	for (long long i = 0; i < MAX_GROUP_NUM; i++)
	{
		if (GroupMisses[i] != 0)
		{
			start = i;
			break;
		}
	}
	for (long long i = MAX_GROUP_NUM - 1; i >= 0; i--)
	{
		if (GroupMisses[i] != 0)
		{
			end = i;
			break;
		}
	}

	for (long long i = start; i < end; i++)
	{
	//	fprintf(f_ins_cache, "%lld:%d\t", i, GroupHitsImage[i]);
		fprintf(f_ins_cache, "%lld:%d\n", i, GroupMisses[i]);
		
		fprintf(f_group_func, "%lld:", i);
		for (std::map<ADDRINT, bool>::iterator iter = GroupFuncs[i].begin();
			iter != GroupFuncs[i].end();
			iter++)
		{
			if (is_in_range(iter->first))
				fprintf(f_group_func, "%08x|", iter->first);
			else
				break;
		}
		fprintf(f_group_func, "\n");
	}

	fclose(f_ins_cache);
	fclose(f_group_func);
}

static bool compare(int a,int b)
{
      return a > b;   //升序排列，如果改为return a < b，则为降序
}

static VOID write_ins_miss(char* file1, char* file2)
{
	FILE * f = fopen(file1, "w");
	FILE * f1 = fopen(file2, "w");

	//fprintf(f, "%lld\n", insts_count);

	//sort(instMissNum.begin(), instMissNum.end(), compare);

	//for (unsigned i = 0; i < inst_miss; i++)
	//{
	//	fprintf(f, "%08x:%d\t", i + LowBound, instMissNum[i]);
	//}

	std::map<int, ADDRINT> tmp;
	std::map<ADDRINT, int> func_miss_count;

	/*for (std::map<ADDRINT, int>::iterator iter = instMissNum.begin();
		iter != instMissNum.end();
		iter++)
	{
		tmp[iter->second] = iter->first;
		func_miss_count[insFuncMap[iter->first]] += iter->second;
	}*/
	for (unsigned int i = 0; i < MAX_INS_NUM; i++)
	{
		if (instMissNum[i] > 0)
		{
			//printf("%08x: %d\n", i + LowBound, instMissNum[i]);

			tmp[instMissNum[i]] = i + LowBound;
			func_miss_count[insFuncMap[i + LowBound]] += instMissNum[i];
		}
	}


	for (std::map<int, ADDRINT>::iterator iter = tmp.begin(); iter != tmp.end(); iter++)
	{
		fprintf(f, "%08x(%08x):%d\n", iter->second, insFuncMap[iter->second], iter->first);
	}

	tmp.clear();
	for (std::map<ADDRINT, int>::iterator iter = func_miss_count.begin(); iter != func_miss_count.end(); iter++)
	{
		tmp[iter->second] = iter->first;
	}

	for (std::map<int, ADDRINT>::iterator iter = tmp.begin(); iter != tmp.end(); iter++)
	{
		if ( is_in_range(iter->second) )
			fprintf(f1, "%08x:%d\n", iter->second, iter->first);
	}


	fclose(f);
	fclose(f1);
	puts("test\n");

}

static VOID Fini(int code, VOID * v)
{
	printf("--------- Instrumentation Done! ---------\n");

    std::ofstream out( KnobOutputFile.Value().c_str() );

    // print D-cache profile
    // @todo what does this print
    // out << "PIN:MEMLATENCIES 1.0. 0x0\n";

    out << "# DCACHE configuration ["
        << "c = " << dl1->CacheSize() / 1024 << "KB, "
        << "b = " << dl1->LineSize() << "B, "
        << "a = " << dl1->Associativity() << "]\n";

    out <<
        "#\n"
        "# DCACHE stats\n"
        "#\n";
    
    out << dl1->StatsLong("# ", CACHE_BASE::CACHE_TYPE_DCACHE);

    if( KnobTrackLoads || KnobTrackStores )
    {
        out <<
            "#\n"
            "# LOAD stats\n"
            "#\n";
        
        out << profile.StringLong();
    }

    out.close();

	//write_time_cache("data/time_cache.log");
	//write_time_func("data/time_func.log");
	//write_ins_cache("data/insts_cache.log", "data/insts_funcs.log");

	write_ins_miss("data/inst_hit.log", "data/func_hit.log");
	
	EndTime = clock();
	printf("------------- Time: %.2lfs ---------------\n", (EndTime - BeginTime) / 1000.0);
}



int dcache(int argc, char *argv[])
{
	BeginTime = clock();
    PIN_InitSymbols();

    if( PIN_Init(argc, argv) )
    {
        return Usage();
    }

    dl1 = new DL1::CACHE("L1 Data Cache", 
                         KnobCacheSize.Value() * KILO,
                         KnobLineSize.Value(),
                         KnobAssociativity.Value());
    
    profile.SetKeyName("iaddr          ");
    profile.SetCounterName("dcache:miss        dcache:hit");

    COUNTER_HIT_MISS threshold;

    threshold[COUNTER_HIT] = KnobThresholdHit.Value();
    threshold[COUNTER_MISS] = KnobThresholdMiss.Value();
    
    profile.SetThreshold( threshold );
    
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

	//puts("b");
    // Never returns
	//memset(interval_miss_nums, 0, sizeof(interval_miss_nums));

	func_stack.push(0);

    PIN_StartProgram();
    
    return 0;
}
