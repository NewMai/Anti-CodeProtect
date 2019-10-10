#include <iostream>
#include <map>
#include <string>
#include <fstream>

#include "kscope.h"

using namespace std;

ConfigReader::ConfigReader()
{
	FileManager LogFile("data/configReader.log", "w");

	codeStartAddr_ = 0xFFFFFFFF;
	codeEndAddr_ = 0xFFFFFFFF;
	switchOnAddr_ = 0xFFFFFFFF;
	switchOffAddr_ = 0xFFFFFFFF;
	detachPoint_ = 0xFFFFFFFF;

	std::ifstream config_fs( "config/kscope.cfg" );
	if ( config_fs.is_open() == false )
	{
		fprintf( LogFile.fp(), "Fail to open config.cfg\r\n" );
	}
	else
	{
		std::string s;
		do
		{
			std::getline( config_fs, s );

			std::string::size_type pos = s.find("=");
			if ( pos != std::string::npos && pos > 0 )
			{
				std::string key = s.substr(0, pos);
				std::string value = s.substr(pos + 1, std::string::npos);
				configMap_[key] = value;
			}
		}
		while ( s != "====" );

		sscanf( configMap_[std::string("codeStartAddr")].c_str(), "%016llx", &codeStartAddr_ );
		sscanf( configMap_[std::string("codeEndAddr")].c_str(), "%016llx", &codeEndAddr_ );
		fprintf( LogFile.fp(), "from %016llx to %016llx\r\n", codeStartAddr_, codeEndAddr_ );

		sscanf( configMap_[std::string("switchOnAddr")].c_str(), "%016llx", &switchOnAddr_ );
		sscanf( configMap_[std::string("switchOffAddr")].c_str(), "%016llx", &switchOffAddr_ );
		fprintf( LogFile.fp(), "switch on and off: %016llx, %016llx\r\n", switchOnAddr_, switchOffAddr_ );

		sscanf( configMap_[std::string("detachPoint")].c_str(), "%016llx", &detachPoint_ );
		fprintf( LogFile.fp(), "detach at: %016llx\r\n", detachPoint_ );

		sscanf( configMap_[std::string("instRecNum")].c_str(), "%d", &instRecNum_ );
		fprintf( LogFile.fp(), "instRecNum: %d\r\n", instRecNum_ );

		sscanf( configMap_[std::string("threadToMonitor")].c_str(), "%016llx", &threadToMonitor_ );
		fprintf( LogFile.fp(), "thread entry: %016llx\r\n", threadToMonitor_ );
	}

	if ( configMap_[std::string("ksFilter")] == std::string("on") )
	{
		std::ifstream af_fs( "config/ksAddrFilter.txt" );
		if ( af_fs.is_open() == false )
		{
			fprintf( LogFile.fp(), "Fail to open AddrFilter txt\r\n" );
		}
		else
		{
			std::string s;
			ADDRINT i;
			while( af_fs )
			{
				std::getline( af_fs, s );
				if ( s.size() >= 8 )
				{
					sscanf( s.c_str(), "%016llx\r\n", &i );
					addrFilter_.insert(i);
				}
 			}
		}
	}
	fprintf( LogFile.fp(), "Addr filter size: %d\r\n", addrFilter_.size() );
}

bool ConfigReader::is_addrSwc_on()
{
	return configMap_[string("ksSwitch")] == string("on");
}

void ConfigReader::set_codeStartAddr(ADDRINT addr)
{
	codeStartAddr_ = addr;
}
void ConfigReader::set_codeEndAddr(ADDRINT addr)
{
	codeEndAddr_ = addr;
}
void ConfigReader::set_dllStartAddr(ADDRINT addr)
{
	m_dllStartAddr = addr;
}
void ConfigReader::set_dllEndAddr(ADDRINT addr)
{
	m_dllEndAddr = addr;
}

ADDRINT ConfigReader::get_codeStartAddr()
{
	return codeStartAddr_;
}

ADDRINT ConfigReader::get_codeEndAddr()
{
	return codeEndAddr_;
}
ADDRINT ConfigReader::get_dllStartAddr()
{
	return m_dllStartAddr;
}

ADDRINT ConfigReader::get_dllEndAddr()
{
	return m_dllEndAddr;
}

ADDRINT ConfigReader::get_switchOnAddr()
{
	return switchOnAddr_;
}

ADDRINT ConfigReader::get_switchOffAddr()
{
	return switchOffAddr_;
}

ADDRINT ConfigReader::get_detachPoint()
{
	return detachPoint_;
}

std::set<ADDRINT> & ConfigReader::get_addrFilter()
{
	return addrFilter_;
}

bool ConfigReader::in_addr_range(ADDRINT pc)
{
	return ( pc >= codeStartAddr_ && pc <= codeEndAddr_ );
}

bool ConfigReader::in_dll_addr_range(ADDRINT pc)
{
	return (pc >= m_dllStartAddr && pc <= m_dllEndAddr);
}

bool ConfigReader::in_addr_set(ADDRINT pc)
{
	return ( addrFilter_.find(pc) != addrFilter_.end() );
}

THREADID ConfigReader::get_threadToMonitor()
{
	return threadToMonitor_;
}

size_t ConfigReader::get_instRecNum()
{
	return instRecNum_;
}