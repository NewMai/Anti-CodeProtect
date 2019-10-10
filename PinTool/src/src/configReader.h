
class ConfigReader
{
public:
	ConfigReader();

	void set_codeStartAddr(ADDRINT addr);
	void set_codeEndAddr(ADDRINT addr);
	void set_dllStartAddr(ADDRINT addr);
	void set_dllEndAddr(ADDRINT addr);

	ADDRINT get_dllStartAddr();
	ADDRINT get_dllEndAddr();

	ADDRINT get_codeStartAddr();
	ADDRINT get_codeEndAddr();
	ADDRINT get_switchOnAddr();
	ADDRINT get_switchOffAddr();
	ADDRINT get_detachPoint();
	THREADID get_threadToMonitor();
	size_t get_instRecNum();
	std::set<ADDRINT>& get_addrFilter();

	bool in_addr_range	(ADDRINT pc);
	bool in_dll_addr_range(ADDRINT pc);
	bool in_addr_set	(ADDRINT pc);
	bool is_addrSwc_on		();

private:
	ADDRINT codeStartAddr_;
	ADDRINT codeEndAddr_;
	ADDRINT m_dllStartAddr;
	ADDRINT m_dllEndAddr;
	ADDRINT switchOnAddr_;
	ADDRINT switchOffAddr_;
	ADDRINT detachPoint_;
	THREADID threadToMonitor_;
	size_t instRecNum_;
	std::set<ADDRINT> addrFilter_;
	std::map<std::string, std::string> configMap_;
};

