/*
   hvtrace.cpp -- HV Mode: the turing-hv hypervisor's NATIVE TRACE (rev150) as an x64dbg run trace.

     HvTrace [address[, count[, stepover]]]
       address   default: the instruction selected in the disassembly
       count     instructions to record, 1..2048 (default 1000)
       stepover  1 = a call's callee runs (followed, not recorded); default 0

   The first user-mode thread of the debuggee to reach the address is followed by the hypervisor one instruction at a
   time -- on any page, into calls and out through returns -- and each instruction's registers (before it ran) are
   recorded. The thread is NEVER stopped: no breakpoint, no debug event, no trap flag it could see. When the trace ends
   the records are written as a normal x64dbg trace file (db\<module>-hvtrace-<time>.trace64) and opened in the Trace
   tab: every instruction with its registers, searchable like any run trace (no memory-access columns: the hypervisor
   records registers only).

   It ends before PUSHF / POPF / IRET / SYSCALL / INT n (they would see or eat the step), at an interrupt or exception
   due for the thread, or after `count`. One trace at a time. HvTraceStop ends a waiting or running trace and keeps
   what it has.
*/
#include "hvtrace.h"
#include "hvmode.h"
#include "debugger.h"
#include "console.h"
#include "value.h"
#include "memory.h"
#include "module.h"
#include "_dbgfunctions.h"
#include "stringutils.h"
#include "jansson/jansson_x64dbg.h"
#include "TitanTuring/TitanTuring.h"
#include <zydis_wrapper.h>
#include <atomic>
#include <thread>
#include <vector>

namespace
{
    std::atomic<uint32_t> gTraceId{0};      // the trace armed / running (0 = none)
    std::atomic<bool> gStop{false};

    decltype(&TT_TraceStart) pStart = nullptr;
    decltype(&TT_TraceRead) pRead = nullptr;
    decltype(&TT_TraceStop) pStopTrace = nullptr;
    decltype(&TT_TraceReason) pReason = nullptr;

    bool bind()
    {
        HMODULE m = hvmodeEngine();
        if(!m)
            return false;
        pStart = reinterpret_cast<decltype(pStart)>(GetProcAddress(m, "TT_TraceStart"));
        pRead = reinterpret_cast<decltype(pRead)>(GetProcAddress(m, "TT_TraceRead"));
        pStopTrace = reinterpret_cast<decltype(pStopTrace)>(GetProcAddress(m, "TT_TraceStop"));
        pReason = reinterpret_cast<decltype(pReason)>(GetProcAddress(m, "TT_TraceReason"));
        return pStart && pRead && pStopTrace && pReason;
    }

    // x64dbg's trace file: the register words of REGDUMP up to lastError (TraceRecordManager's REGDUMPWORD)
    typedef union
    {
        REGDUMP registers;
        duint regword[(FIELD_OFFSET(REGDUMP, lastError) + sizeof(DWORD)) / sizeof(duint)];
    } REGWORDS;
    const unsigned FULL_DUMP_EVERY = 512;   // as TraceRecord.cpp: a full register dump starts each reader "page"

    void fill(REGWORDS & w, const TT_TRACE_REC & r)
    {
        memset(&w, 0, sizeof(w));
        auto & c = w.registers.regcontext;
        c.cax = duint(r.gpr[0]); c.ccx = duint(r.gpr[1]); c.cdx = duint(r.gpr[2]); c.cbx = duint(r.gpr[3]);
        c.csp = duint(r.rsp); c.cbp = duint(r.gpr[5]); c.csi = duint(r.gpr[6]); c.cdi = duint(r.gpr[7]);
#ifdef _WIN64
        c.r8 = r.gpr[8]; c.r9 = r.gpr[9]; c.r10 = r.gpr[10]; c.r11 = r.gpr[11];
        c.r12 = r.gpr[12]; c.r13 = r.gpr[13]; c.r14 = r.gpr[14]; c.r15 = r.gpr[15];
#endif
        c.cip = duint(r.rip);
        c.eflags = duint(r.rflags);
        auto & f = w.registers.flags;
        f.c = (r.rflags & 0x1) != 0; f.p = (r.rflags & 0x4) != 0; f.a = (r.rflags & 0x10) != 0; f.z = (r.rflags & 0x40) != 0;
        f.s = (r.rflags & 0x80) != 0; f.t = (r.rflags & 0x100) != 0; f.i = (r.rflags & 0x200) != 0; f.d = (r.rflags & 0x400) != 0;
        f.o = (r.rflags & 0x800) != 0;
        // segments, x87 / SSE, last error: not recorded by the hypervisor -- left 0
    }

    bool writeTrace(const std::string & path, const std::vector<TT_TRACE_REC> & recs, DWORD tid)
    {
        HANDLE h = CreateFileW(StringUtils::Utf8ToUtf16(path).c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if(h == INVALID_HANDLE_VALUE)
            return false;
        std::vector<unsigned char> out;
        // header: "TRAC", the JSON's size, the JSON (as TraceRecordManager::enableTraceRecording writes it)
        json_t* root = json_object();
        json_object_set_new(root, "ver", json_integer(1));
        json_object_set_new(root, "arch", json_string(ArchValue("x86", "x64")));
        json_object_set_new(root, "hashAlgorithm", json_string("murmurhash"));
        json_object_set_new(root, "hash", json_hex(dbgfunctionsget()->DbGetHash()));
        json_object_set_new(root, "compression", json_string(""));
        char mpath[MAX_PATH] = "";
        ModPathFromAddr(dbgdebuggedbase(), mpath, MAX_PATH);
        json_object_set_new(root, "path", json_string(mpath));
        char* hdr = json_dumps(root, JSON_COMPACT);
        const uint32_t hlen = uint32_t(strlen(hdr));
        out.insert(out.end(), { 'T', 'R', 'A', 'C' });
        out.insert(out.end(), reinterpret_cast<const unsigned char*>(&hlen), reinterpret_cast<const unsigned char*>(&hlen) + 4);
        out.insert(out.end(), hdr, hdr + hlen);
        json_free(hdr);
        json_decref(root);

        const size_t nwords = (FIELD_OFFSET(REGDUMP, lastError) + sizeof(DWORD)) / sizeof(duint);
        REGWORDS prev, cur;
        memset(&prev, 0, sizeof(prev));
        for(size_t k = 0; k < recs.size(); k++)
        {
            fill(cur, recs[k]);
            const bool full = (k % FULL_DUMP_EVERY) == 0;
            unsigned char opcode[16] = {};
            unsigned char opsize = 0;
            {
                unsigned char buf[MAX_DISASM_BUFFER] = {};
                duint got = 0;
                MemRead(duint(recs[k].rip), buf, sizeof(buf), &got);
                Zydis z;
                if(got && z.DisassembleSafe(recs[k].rip, buf, size_t(got)))
                    opsize = static_cast<unsigned char>(z.Size() & 0x0F);
                if(k + 1 < recs.size() && recs[k + 1].rip > recs[k].rip && recs[k + 1].rip - recs[k].rip <= 15 && !opsize)
                    opsize = static_cast<unsigned char>(recs[k + 1].rip - recs[k].rip);
                memcpy(opcode, buf, opsize);
            }
            std::vector<unsigned char> pos;
            std::vector<duint> val;
            int last = -1;
            for(size_t i = 0; i < nwords; i++)
            {
                if(full || cur.regword[i] != prev.regword[i])
                {
                    pos.push_back(static_cast<unsigned char>(int(i) - last - 1));
                    val.push_back(cur.regword[i]);
                    last = int(i);
                }
            }
            out.push_back(0);                                   // block type: an instruction
            out.push_back(static_cast<unsigned char>(pos.size()));           // registers changed
            out.push_back(0);                                   // memory accesses: none recorded
            out.push_back(static_cast<unsigned char>((full ? 0x80 : 0) | opsize));
            if(full)
                out.insert(out.end(), reinterpret_cast<const unsigned char*>(&tid), reinterpret_cast<const unsigned char*>(&tid) + 4);
            out.insert(out.end(), opcode, opcode + opsize);
            out.insert(out.end(), pos.begin(), pos.end());
            out.insert(out.end(), reinterpret_cast<const unsigned char*>(val.data()), reinterpret_cast<const unsigned char*>(val.data() + val.size()));
            prev = cur;
        }
        DWORD written = 0;
        const bool ok = WriteFile(h, out.data(), DWORD(out.size()), &written, nullptr) && written == out.size();
        CloseHandle(h);
        return ok;
    }

    std::string tracePath()
    {
        char mod[MAX_MODULE_SIZE] = "hvtrace";
        ModNameFromAddr(dbgdebuggedbase(), mod, false);
        SYSTEMTIME t;
        GetLocalTime(&t);
        std::string dir = std::string(szUserDir) + "\\db";
        if(GetFileAttributesW(StringUtils::Utf8ToUtf16(dir).c_str()) == INVALID_FILE_ATTRIBUTES)
            dir = szUserDir;
        return StringUtils::sprintf("%s\\%s-hvtrace-%04u%02u%02u-%02u%02u%02u.trace64", dir.c_str(), mod, t.wYear, t.wMonth, t.wDay,
                                    t.wHour, t.wMinute, t.wSecond);
    }

    void worker(uint32_t id, duint address, uint32_t count)
    {
        TT_TRACE_INFO info = {};
        uint32_t n = 0;
        const ULONGLONG t0 = GetTickCount64();
        bool armedLogged = false;
        for(;;)                                             // until it ends, is stopped, or nobody reached it in 2 min
        {
            if(!pRead(id, &info, nullptr, 0, &n))
            {
                dprintf(QT_TRANSLATE_NOOP("DBG", "HvTrace: the hypervisor lost the trace\n"));
                gTraceId = 0;
                return;
            }
            if(info.state == 3 || gStop)
                break;
            if(info.state == 2 && !armedLogged)
            {
                dprintf(QT_TRANSLATE_NOOP("DBG", "HvTrace: thread %u reached %p -- recording\n"), DWORD(info.tid), address);
                armedLogged = true;
            }
            if(info.state == 1 && GetTickCount64() - t0 > 120000)
            {
                dprintf(QT_TRANSLATE_NOOP("DBG", "HvTrace: no thread reached %p in 2 minutes -- stopped\n"), address);
                pStopTrace(id);
                gTraceId = 0;
                return;
            }
            Sleep(100);
        }
        std::vector<TT_TRACE_REC> recs(count ? count : 2048);
        if(!pRead(id, &info, recs.data(), uint32_t(recs.size()), &n))
            n = 0;
        recs.resize(n);
        pStopTrace(id);
        gTraceId = 0;
        if(!n)
        {
            dprintf(QT_TRANSLATE_NOOP("DBG", "HvTrace: stopped before any thread reached %p\n"), address);
            return;
        }
        const char* why = info.state == 3 ? pReason(info.reason) : "stopped by you while it ran";
        const double us = info.tsc_hz && info.end_tsc > info.start_tsc ? double(info.end_tsc - info.start_tsc) * 1e6 / double(info.tsc_hz) : 0.0;
        const std::string path = tracePath();
        if(!writeTrace(path, recs, DWORD(info.tid)))
        {
            dprintf(QT_TRANSLATE_NOOP("DBG", "HvTrace: could not write %s\n"), path.c_str());
            return;
        }
        dprintf(QT_TRANSLATE_NOOP("DBG", "HvTrace: %u instructions of thread %u from %p (%llu stepped, %.0f us, %u pauses for Hyper-V) -- ended: %s\n"),
                n, DWORD(info.tid), address, (unsigned long long)info.steps, us, info.pauses, why);
        dprintf(QT_TRANSLATE_NOOP("DBG", "HvTrace: written to %s (opened in the Trace tab)\n"), path.c_str());
        GuiOpenTraceFile(path.c_str());
    }
}

bool cbHvTrace(int argc, char* argv[])
{
    if(!hvmodeActive() || !bind())
    {
        dputs(QT_TRANSLATE_NOOP("DBG", "HvTrace: HV Mode only (the hypervisor's trace)"));
        return false;
    }
    if(gTraceId)
    {
        dputs(QT_TRANSLATE_NOOP("DBG", "HvTrace: a trace is already armed or running (HvTraceStop ends it)"));
        return false;
    }
    duint address = 0;
    if(argc > 1)
    {
        if(!valfromstring(argv[1], &address, false))
            return false;
    }
    else
    {
        SELECTIONDATA sel = {};
        if(!GuiSelectionGet(GUI_DISASSEMBLY, &sel) || !sel.start)
        {
            dputs(QT_TRANSLATE_NOOP("DBG", "HvTrace: no address given and nothing selected in the disassembly"));
            return false;
        }
        address = sel.start;
    }
    duint count = 1000;
    if(argc > 2 && !valfromstring(argv[2], &count, false))
        return false;
    if(!count || count > 2048)
    {
        dputs(QT_TRANSLATE_NOOP("DBG", "HvTrace: count is 1..2048"));
        return false;
    }
    duint over = 0;
    if(argc > 3 && !valfromstring(argv[3], &over, false))
        return false;

    // the instruction's length (the hypervisor watches its page(s))
    unsigned char buf[MAX_DISASM_BUFFER] = {};
    duint got = 0;
    uint32_t len = 1;
    Zydis z;
    if(MemRead(address, buf, sizeof(buf), &got) && got && z.DisassembleSafe(address, buf, size_t(got)) && z.Size())
        len = z.Size();

    char why[256] = "";
    uint32_t id = 0;
    if(!pStart(uint64_t(address), len, uint32_t(count), over != 0, &id, why, sizeof(why)))
    {
        dprintf(QT_TRANSLATE_NOOP("DBG", "HvTrace: %s\n"), why);
        return false;
    }
    gStop = false;
    gTraceId = id;
    dprintf(QT_TRANSLATE_NOOP("DBG", "HvTrace: armed at %p (%u instructions%s) -- the first thread to reach it is traced; it will not be stopped\n"),
            address, uint32_t(count), over ? ", stepping over calls" : "");
    std::thread(worker, id, address, uint32_t(count)).detach();
    return true;
}

bool cbHvTraceStop(int argc, char* argv[])
{
    if(!gTraceId)
    {
        dputs(QT_TRANSLATE_NOOP("DBG", "HvTrace: no trace armed"));
        return false;
    }
    gStop = true;                     // the worker reads what was recorded, then ends it
    return true;
}
