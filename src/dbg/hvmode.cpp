/**
 @file hvmode.cpp

 @brief HV Mode: x64dbg debugs through the turing-hv hypervisor and touches no other process the Windows way.

 In HV Mode:
   - the debug engine is TitanTuring.dll (the hypervisor) instead of the stock TitanEngine.dll (the Windows debugger).
     x64dbg.dll delay-loads "TitanEngine.dll"; the delay-load hook below hands it whichever engine the mode wants, and a
     runtime switch unbinds the engine so the next call re-binds (/DELAY:UNLOAD).
   - TitanTuring's guard is on: NO module in this process can obtain a handle to any other process or thread (the
     handle-creating system calls are refused inside our own ntdll). Every read, debug attach, remote thread, suspend,
     ... needs such a handle first, so none can happen. A refusal is logged and warned about -- it never fails silently.
   - x64dbg.dll's own Windows calls about the debuggee are routed through TitanTuring's shim (pseudo-handles).
 HV Mode is ON by default. If it is on but the guard can't be installed, x64dbg refuses to start and says why
 (fail closed); HvMode=0 under [Engine] in x64dbg.ini starts it as the standard Windows debugger. The `hvmode`
 command switches for THIS SESSION only -- it never changes the startup default, so a test or a moment's `hvmode off`
 can't leave the next start (maybe on a game) as the Windows debugger. The title says [HV Mode] or [HV Mode OFF].
 */

#include "hvmode.h"
#include "console.h"
#include "debugger.h"
#include "_exports.h"
#include "stringutils.h"
#include "handle.h"
#include "TitanTuring/TitanTuring.h"
#include <delayimp.h>
#include <set>

namespace
{
    HMODULE gEngine = nullptr;          // TitanTuring.dll (pinned by its guard once installed)
    volatile bool gActive = false;      // the guard is refusing (HV Mode fully on)
    volatile LONG gWant = -1;           // which engine x64dbg.dll must bind: 1 = TitanTuring, 0 = stock, -1 = not read yet
    HANDLE gWatcher = nullptr;

    // The engine choice comes from the setting, NOT from init order: the GUI applies its settings (SetEngineVariable,
    // an engine call) before DbgInit, and whatever the first engine call binds stays bound.
    bool wantHv()
    {
        if(gWant < 0)
        {
            duint setting = 1;          // default: ON
            BridgeSettingGetUint("Engine", "HvMode", &setting);
            InterlockedCompareExchange(&gWant, setting ? 1 : 0, -1);
        }
        return gWant == 1;
    }

    decltype(&TT_EnterHvMode) pEnter = nullptr;
    decltype(&TT_LeaveHvMode) pLeave = nullptr;
    decltype(&TT_TakeRefusal) pTake = nullptr;
    decltype(&TT_RefusalsDropped) pDropped = nullptr;
    decltype(&TT_ProcessImagePath) pImagePath = nullptr;

    std::wstring programDir()
    {
        wchar_t path[MAX_PATH] = L"";
        GetModuleFileNameW(hInst, path, MAX_PATH);
        std::wstring p(path);
        return p.substr(0, p.find_last_of(L"\\/") + 1);
    }

    bool loadEngine(std::string & error)
    {
        if(gEngine)
            return true;
        const std::wstring path = programDir() + L"TitanTuring.dll";
        HMODULE m = LoadLibraryW(path.c_str());
        if(!m)
        {
            error = StringUtils::sprintf("cannot load %s (error %u)", StringUtils::Utf16ToUtf8(path).c_str(), GetLastError());
            return false;
        }
#define GETFN(var, name) var = reinterpret_cast<decltype(var)>(GetProcAddress(m, name)); if(!var) { error = "TitanTuring.dll has no " name; FreeLibrary(m); return false; }
        GETFN(pEnter, "TT_EnterHvMode")
        GETFN(pLeave, "TT_LeaveHvMode")
        GETFN(pTake, "TT_TakeRefusal")
        GETFN(pDropped, "TT_RefusalsDropped")
        GETFN(pImagePath, "TT_ProcessImagePath")
#undef GETFN
        gEngine = m;
        return true;
    }

    std::string moduleOf(uint64_t address)
    {
        HMODULE m = nullptr;
        wchar_t path[MAX_PATH] = L"";
        if(address && GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                         reinterpret_cast<LPCWSTR>(uintptr_t(address)), &m) && GetModuleFileNameW(m, path, MAX_PATH))
        {
            std::wstring p(path);
            return StringUtils::Utf16ToUtf8(p.substr(p.find_last_of(L"\\/") + 1));
        }
        return address ? StringUtils::sprintf("code at %p", (void*)uintptr_t(address)) : "x64dbg";
    }

    std::string processName(DWORD pid)
    {
        wchar_t path[MAX_PATH] = L"";
        if(pid && pImagePath && pImagePath(pid, path, MAX_PATH, true))
        {
            std::wstring p(path);
            return StringUtils::Utf16ToUtf8(p.substr(p.find_last_of(L"\\/") + 1));
        }
        return pid ? "?" : "another process";
    }

    // every refusal is logged (log window + <user dir>\hvmode.log) and shown in the status bar -- never a modal box: a
    // background refusal must not block x64dbg (one did, holding up its close)
    void report(const TT_REFUSAL & r, std::set<std::string> & warned)
    {
        const std::string who = moduleOf(r.caller);
        std::string what, key;
        switch(r.kind)
        {
        case TT_REFUSE_OPEN_PROCESS:
            what = StringUtils::sprintf("%s tried to open process %s (pid %u, access 0x%X)", who.c_str(), processName(r.pid).c_str(), r.pid, r.access);
            key = StringUtils::sprintf("p%u:%s", r.pid, who.c_str());
            break;
        case TT_REFUSE_OPEN_THREAD:
            what = StringUtils::sprintf("%s tried to open thread %u of process %s (pid %u, access 0x%X)", who.c_str(), r.tid, processName(r.pid).c_str(), r.pid, r.access);
            key = StringUtils::sprintf("t%u:%s", r.pid, who.c_str());
            break;
        case TT_REFUSE_NEXT_PROCESS:
            what = StringUtils::sprintf("%s tried to walk every process by handle (NtGetNextProcess)", who.c_str());
            key = "n:" + who;
            break;
        default:
            what = StringUtils::sprintf("%s asked to %s (process %s, pid %u)", who.c_str(), r.what, processName(r.pid).c_str(), r.pid);
            key = std::string("s:") + r.what;
            break;
        }
        const std::string text = "HV Mode refused: " + what + ". In HV Mode x64dbg leaves no Windows-visible trace on other processes; "
                                 "leave HV Mode (command: hvmode off, when not debugging) to do this.";
        dprintf_untranslated("[HV Mode] %s\n", text.c_str());
        // a lasting record next to the database folder: <user dir>\hvmode.log
        SYSTEMTIME st;
        GetLocalTime(&st);
        const std::wstring logPath = StringUtils::Utf8ToUtf16(szUserDir) + L"\\hvmode.log";
        HANDLE f = CreateFileW(logPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if(f != INVALID_HANDLE_VALUE)
        {
            const std::string line = StringUtils::sprintf("%04u-%02u-%02u %02u:%02u:%02u  %s\r\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, text.c_str());
            DWORD written = 0;
            WriteFile(f, line.data(), DWORD(line.size()), &written, nullptr);
            CloseHandle(f);
        }
        if(warned.insert(key).second)
            GuiAddStatusBarMessage(("[HV Mode] refused: " + what + " -- see the log\n").c_str());
    }

    DWORD WINAPI watcherThread(LPVOID)
    {
        std::set<std::string> warned;
        DWORD reportedDropped = 0;
        for(;;)
        {
            TT_REFUSAL r;
            while(pTake && pTake(&r))
                report(r, warned);
            const DWORD dropped = pDropped ? pDropped() : 0;
            if(dropped != reportedDropped)
            {
                dprintf_untranslated("[HV Mode] %u more refusals were not itemised (the queue was full) -- all were refused.\n", dropped - reportedDropped);
                reportedDropped = dropped;
            }
            Sleep(200);
        }
    }

    bool enter(std::string & error)
    {
        if(!loadEngine(error))
            return false;
        HMODULE routed[] = { hInst, GetModuleHandleW(L"dbghelp.dll") };
        char why[512] = "";
        if(!pEnter(routed, DWORD(_countof(routed)), why, sizeof(why)))
        {
            error = *why ? why : "TitanTuring refused to enter HV Mode";
            return false;
        }
        gActive = true;
        if(!gWatcher)
            gWatcher = CreateThread(nullptr, 0, watcherThread, nullptr, 0, nullptr);
        return true;
    }

    // the delay-load hook: "TitanEngine.dll" is TitanTuring.dll whenever HV Mode is wanted -- from the very first engine
    // call, guard installed or not (TitanTuring refuses to attach until its guard is active)
    FARPROC WINAPI hvDelayHook(unsigned notify, PDelayLoadInfo info)
    {
        if(notify == dliNotePreLoadLibrary && _stricmp(info->szDll, "TitanEngine.dll") == 0 && wantHv())
        {
            std::string error;
            if(loadEngine(error))
                return reinterpret_cast<FARPROC>(gEngine);
            // TitanTuring.dll can't load: the stock engine binds, and hvmodeInit refuses to start x64dbg
        }
        return nullptr;
    }
}

extern "C" const PfnDliHook __pfnDliNotifyHook2 = hvDelayHook;

const char* hvmodeInit()
{
    if(!wantHv())
    {
        dputs_untranslated("HV Mode is OFF: x64dbg is the standard Windows debugger (command: hvmode on). HvMode=0 in x64dbg.ini sets this.");
        GuiUpdateWindowTitle("[HV Mode OFF]");
        return nullptr;
    }
    std::string error;
    if(!enter(error))
    {
        static std::string message;
        message = "HV Mode could not start: " + error +
                  "\n\nx64dbg does not run in HV Mode without its guard (nothing would stop it opening the target). "
                  "To use x64dbg as the standard Windows debugger instead, set HvMode=0 under [Engine] in x64dbg.ini.";
        return message.c_str();
    }
    // re-bind through the hook from here on: whatever an earlier engine call bound, the next one binds TitanTuring
    __FUnloadDelayLoadedDLL2("TitanEngine.dll");
    if(GetModuleHandleW(L"TitanEngine.dll"))
    {
        static std::string message;
        message = "HV Mode could not start: the stock debug engine (TitanEngine.dll, the Windows debugger) is loaded in this "
                  "process and could not be unloaded. Report this; to use x64dbg as the standard Windows debugger instead, "
                  "set HvMode=0 under [Engine] in x64dbg.ini.";
        return message.c_str();
    }
    dputs_untranslated("HV Mode is ON: x64dbg debugs through the hypervisor. It opens no handle to any other process or thread, "
                       "never reads or writes them through Windows and never attaches the Windows debugger; anything that would is "
                       "refused and reported. Command: hvmode off (when not debugging) to leave it.");
    GuiUpdateWindowTitle("[HV Mode]");
    return nullptr;
}

bool hvmodeActive()
{
    return gActive;
}

HMODULE hvmodeEngine()
{
    return gActive ? gEngine : nullptr;
}

std::string hvmodeTitle(const char* title)
{
    return std::string(gActive ? "[HV Mode] " : "[HV Mode OFF] ") + title;
}

bool hvmodeSet(bool on, std::string & error)
{
    if(on == gActive)
        return true;
    if(DbgIsDebugging())
    {
        error = "stop debugging first (the engine can't change under a debuggee)";
        return false;
    }
    if(on)
    {
        if(!enter(error))
            return false;
    }
    else
    {
        char why[256] = "";
        if(!pLeave(why, sizeof(why)))
        {
            error = *why ? why : "TitanTuring refused to leave HV Mode";
            return false;
        }
        gActive = false;
    }
    InterlockedExchange(&gWant, on ? 1 : 0);     // this session only: the startup default stays what x64dbg.ini says
    // unbind the engine; the next engine call re-binds through hvDelayHook (TitanTuring.dll itself stays loaded:
    // its guard pinned it), then the engine settings are applied to the new engine
    __FUnloadDelayLoadedDLL2("TitanEngine.dll");
    _dbg_sendmessage(DBG_SETTINGS_UPDATED, nullptr, nullptr);
    GuiUpdateWindowTitle(on ? "[HV Mode]" : "[HV Mode OFF]");
    return true;
}

bool hvmodeListProcesses(std::vector<PROCESSENTRY32>* infoList, std::vector<std::string>* commandList, std::vector<std::string>* winTextList)
{
    infoList->clear();
    // CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) is the system's process list: no handle on any process
    Handle snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(!snap)
        return false;
    PROCESSENTRY32 pe32 = {};
    pe32.dwSize = sizeof(pe32);
    if(!Process32First(snap, &pe32))
        return false;
    do
    {
        if(pe32.th32ProcessID == GetCurrentProcessId() || pe32.th32ProcessID == 0 || pe32.th32ProcessID == 4)
            continue;
        wchar_t path[MAX_PATH] = L"";
        if(pImagePath && pImagePath(pe32.th32ProcessID, path, MAX_PATH, true))
            strncpy_s(pe32.szExeFile, StringUtils::Utf16ToUtf8(path).c_str(), _TRUNCATE);
        infoList->push_back(pe32);
        if(!dbggetwintext(winTextList, pe32.th32ProcessID))   // window captions: read without messaging the process
            winTextList->push_back("");
        commandList->push_back("");                           // command lines live in each process's memory: not read
    }
    while(Process32Next(snap, &pe32));
    return true;
}

bool cbHvMode(int argc, char* argv[])
{
    if(argc < 2)
    {
        dprintf_untranslated("HV Mode is %s. Usage: hvmode [on|off]\n", gActive ? "ON" : "OFF");
        return true;
    }
    const std::string a = StringUtils::ToLower(argv[1]);
    bool on;
    if(a == "on" || a == "1")
        on = true;
    else if(a == "off" || a == "0")
        on = false;
    else
    {
        dputs_untranslated("Usage: hvmode [on|off]");
        return false;
    }
    std::string error;
    if(!hvmodeSet(on, error))
    {
        dprintf_untranslated("HV Mode: %s\n", error.c_str());
        return false;
    }
    dprintf_untranslated(on ? "HV Mode is ON: x64dbg debugs through the hypervisor and opens no other process.\n"
                         : "HV Mode is OFF: x64dbg is the standard Windows debugger (it opens processes and attaches the Windows debugger) -- "
                           "for this session only; x64dbg starts in HV Mode again next time.\n");
    return true;
}
