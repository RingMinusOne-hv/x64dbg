// hvmode.h -- HV Mode: x64dbg debugs through the turing-hv hypervisor (TitanTuring.dll) and touches no other process
// the Windows way. See hvmode.cpp and src/dbg/TitanTuring/README.md.
#pragma once

#include "_global.h"
#include <tlhelp32.h>

// Before the first engine call (top of _dbg_dbginit): choose the engine and, in HV Mode, install the guard.
// nullptr = fine; otherwise the reason x64dbg must not start (HV Mode is on but its guard can't be guaranteed).
const char* hvmodeInit();
bool hvmodeActive();
HMODULE hvmodeEngine();                                  // TitanTuring.dll while HV Mode is active, else nullptr
bool hvmodeSet(bool on, std::string & error);           // runtime switch; refused while debugging
std::string hvmodeTitle(const char* title);              // "[HV Mode] " + title while active
// the attach list without opening any process (system process list + image path by pid)
bool hvmodeListProcesses(std::vector<PROCESSENTRY32>* infoList, std::vector<std::string>* commandList, std::vector<std::string>* winTextList);
bool cbHvMode(int argc, char* argv[]);                  // the `hvmode [on|off]` command
