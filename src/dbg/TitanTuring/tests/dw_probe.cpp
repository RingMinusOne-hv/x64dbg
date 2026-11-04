// dw_probe.cpp -- why a watch on adbg_target's cold_target page never fires (2026-11-03, rev150): arm it through the
// bridge on a FRESH target and print the watch's own counters every 250 ms; then park + step on hot_target (the
// sequence that fails), and arm cold_target again. Tells "the page never faults" (hits/other/elsewhere stay 0: a stale
// executable translation, or the arm never reached the tables) from "it faults but is not attributed".
//   dw_probe.exe <thvbridge.exe> <adbg_target.exe>
#include "../thvclient.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>

static ThvClient c;
static uint64_t g_cr3;

static void line(const char* what, uint32_t r, const thv_dwatch_status& s)
{
    printf("  %-14s r=%08x active=%x pages=%u hits=%llu other=%llu elsewhere=%llu dropped=%llu unstepped=%llu entries=%u count=%u thr=%u paused=%u\n",
           what, r, s.active, s.pages, (unsigned long long)s.hits, (unsigned long long)s.other, (unsigned long long)s.elsewhere,
           (unsigned long long)s.dropped, (unsigned long long)s.unstepped, s.entries, s.count, s.throttled, s.paused);
}

// a capture (snapshot) on `addr`: 1 hit, then disarm. true = it hit within `ms`
static bool capture(const char* name, uint64_t addr, DWORD ms)
{
    thv_capture_cfg cfg = {};
    cfg.max_hits = 1;
    cfg.stack_bytes = 64;
    uint32_t id = 0;
    thv_dwatch_status st = {};
    uint32_t r = c.CaptureArm(g_cr3, addr, 1, nullptr, cfg, &id, &st);
    printf("%s: capture armed r=%08x id=%u\n", name, r, id);
    if(r != THV_OK) return false;
    bool hit = false;
    thv_capture_rec rec = {};
    for(DWORD t0 = GetTickCount(); GetTickCount() - t0 < ms; Sleep(250))
    {
        r = c.CapRead(id, 0, &rec, &st);
        line("capture", r, st);
        if(r == THV_OK && st.count && rec.seq) { hit = true; printf("  HIT rip=%llx tid=%llu\n", (unsigned long long)rec.rip, (unsigned long long)rec.tid); break; }
    }
    c.DwatchClear(id, &st);
    printf("%s: %s\n", name, hit ? "HIT" : "NEVER HIT");
    return hit;
}

static bool trace(const char* name, uint64_t addr, DWORD ms)
{
    uint32_t id = 0;
    thv_dwatch_status st = {};
    uint32_t r = c.TraceArm(g_cr3, addr, 1, 500, 0, &id, &st);
    printf("%s: trace armed r=%08x id=%u\n", name, r, id);
    if(r != THV_OK) return false;
    thv_trace_info info = {};
    std::vector<thv_trace_rec> recs;
    bool done = false;
    for(DWORD t0 = GetTickCount(); GetTickCount() - t0 < ms; Sleep(250))
    {
        r = c.TraceRead(id, 0, 0, &info, recs, &st);
        line("trace", r, st);
        if(r == THV_OK && info.state == THV_TRS_DONE) { done = true; break; }
    }
    printf("  info state=%u reason=%u count=%u steps=%llu tid=%llu\n", info.state, info.reason, info.count, (unsigned long long)info.steps, (unsigned long long)info.tid);
    c.DwatchClear(id, &st);
    printf("%s: %s\n", name, done ? "RAN" : "NEVER CLAIMED");
    return done;
}

static void parkAndStep(uint64_t hot)
{
    uint32_t id = 0;
    thv_dwatch_status st = {};
    uint32_t r = c.BreakArm(g_cr3, hot, 1, nullptr, &id, &st);
    printf("park+step on hot_target: armed r=%08x id=%u\n", r, id);
    thv_capture_rec rec = {};
    auto wait = [&](uint32_t notSeq) {
        for(DWORD t0 = GetTickCount(); GetTickCount() - t0 < 3000; Sleep(20))
        {
            r = c.BreakRead(id, 0, &rec, &st);
            if(r == THV_OK && st.count && st.paused == THV_BKS_HELD && st.entries != notSeq) return true;
        }
        return false;
    };
    if(!wait(~0u)) { printf("  no park\n"); c.DwatchClear(id, &st); return; }
    printf("  parked tid=%llu rip=%llx hold=%u\n", (unsigned long long)rec.tid, (unsigned long long)rec.rip, st.entries);
    for(int i = 0; i < 2; i++)
    {
        thv_break_cmd k = {};
        k.tid = rec.tid;
        k.cmd = THV_BKC_STEP;
        const uint32_t seq = st.entries;
        c.BreakCmd(id, k, &st);
        const bool ok = wait(seq);
        printf("  step %d: %s rip=%llx hold=%u state=%u\n", i + 1, ok ? "landed" : "NO LAND", (unsigned long long)rec.rip, st.entries, st.paused);
    }
    c.DwatchClear(id, &st);
    printf("  cleared\n");
}

int wmain(int argc, wchar_t** argv)
{
    if(argc < 3) { printf("usage: dw_probe <thvbridge.exe> <adbg_target.exe>\n"); return 2; }
    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    HANDLE rd = nullptr, wr = nullptr;
    CreatePipe(&rd, &wr, &sa, 0);
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si = {sizeof(si)};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr; si.hStdError = wr; si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi = {};
    std::wstring cmd = L"\"" + std::wstring(argv[2]) + L"\" --seconds 90 --quiet";
    if(!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) { printf("target start failed\n"); return 1; }
    CloseHandle(wr);
    std::string out;
    uint64_t hot = 0, cold = 0;
    for(DWORD t0 = GetTickCount(); !cold && GetTickCount() - t0 < 10000;)
    {
        char buf[512]; DWORD n = 0;
        if(!ReadFile(rd, buf, sizeof(buf) - 1, &n, nullptr) || !n) break;
        buf[n] = 0; out += buf;
        size_t p = out.find("hot_target="), q = out.find("cold_target=");
        if(p != std::string::npos && q != std::string::npos && out.find(' ', q) != std::string::npos)
        {
            hot = _strtoui64(out.c_str() + p + 11, nullptr, 16);
            cold = _strtoui64(out.c_str() + q + 12, nullptr, 16);
        }
    }
    if(!cold) { printf("no bait line\n"); TerminateProcess(pi.hProcess, 0); return 1; }
    if(!c.Start(argv[1]) || c.OpenStatus() != THV_OK) { printf("bridge: %s\n", c.LastError().c_str()); TerminateProcess(pi.hProcess, 0); return 1; }
    thv_process_info info = {};
    c.ProcessInfo(pi.dwProcessId, &info);
    g_cr3 = info.dirbase;
    printf("target pid %lu hot %llx cold %llx cr3 %llx\n", pi.dwProcessId, (unsigned long long)hot, (unsigned long long)cold, (unsigned long long)g_cr3);

    printf("\n== A. fresh target\n");
    const bool a1 = capture("cold capture", cold, 4000);
    const bool a2 = trace("cold trace", cold, 4000);
    const bool a3 = capture("hot capture", hot, 3000);
    printf("\n== B. park + 2 steps on hot_target\n");
    parkAndStep(hot);
    printf("\n== C. after it\n");
    const bool c1 = capture("cold capture", cold, 4000);
    const bool c2 = trace("cold trace", cold, 4000);
    const bool c3 = capture("hot capture", hot, 3000);
    TerminateProcess(pi.hProcess, 0);
    printf("\nSUMMARY fresh: cold-capture %d cold-trace %d hot-capture %d | after park+step: cold-capture %d cold-trace %d hot-capture %d\n",
           a1, a2, a3, c1, c2, c3);
    return 0;
}
