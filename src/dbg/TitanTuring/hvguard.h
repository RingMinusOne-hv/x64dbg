// hvguard.h -- HV Mode's guard (see hvguard.cpp). Lives in TitanTuring.dll; the module pins itself once the guard is
// installed, so the hooks it plants can never point at unloaded code.
#pragma once
#include "TitanTuring.h"           // TT_REFUSAL, TT_REFUSAL_KIND

namespace hvguard
{
    // Install the hooks (once per process; idempotent). False + `why` when the guard cannot be guaranteed -- e.g.
    // ntdll's stubs aren't the shape we verify (another program already patched them). Fail closed: HV Mode must not
    // start without its guard.
    bool Install(char* why, size_t whyLen);
    bool Installed();
    void SetActive(bool on);        // the hooks stay; this decides whether they refuse
    bool Active();
    // the shim's refusals go in the same queue, so x64dbg reports every refusal the same way
    void Record(uint32_t kind, uint32_t pid, uint32_t tid, uint32_t access, uint64_t caller, const char* what);
    bool Take(TT_REFUSAL* out);     // oldest first; false when empty
    uint32_t Dropped();             // refusals lost because the queue was full (still refused, only not reported)
    DWORD OwnerOfThread(DWORD tid); // the process a thread belongs to, from the system's process list (no handle)
}
