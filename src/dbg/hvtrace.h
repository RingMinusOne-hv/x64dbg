// hvtrace.h -- HV Mode: the turing-hv hypervisor's NATIVE TRACE as an x64dbg run trace (see hvtrace.cpp).
#pragma once

#include "_global.h"

bool cbHvTrace(int argc, char* argv[]);       // HvTrace [address[, count[, stepover]]]
bool cbHvTraceStop(int argc, char* argv[]);   // HvTraceStop: end the waiting / running trace, keep what it recorded
