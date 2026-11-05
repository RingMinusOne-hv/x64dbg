// thvclient.cpp -- see thvclient.h. A line-for-line port of Cheat Engine's TThvBridge (turinghvbridge.pas): the same
// section layout, the same inheritable events, the same "--section <handle>" launch, the same per-slot sequence
// numbers and the same retire-a-slot-on-timeout rule (a late answer must never land on the next user's data).
#include "thvclient.h"
#include <cstring>

static_assert(sizeof(thvb_slot) <= THVB_PAGE, "slot header must fit its page");
static_assert(offsetof(thvb_shared, req_event) == 48, "thvb_shared.req_event");
static_assert(offsetof(thvb_shared, rsp_event) == 560, "thvb_shared.rsp_event");
static_assert(offsetof(thvb_slot, arg) == 24 && offsetof(thvb_slot, ret) == 152 && offsetof(thvb_slot, ret_seq) == 280,
              "thvb_slot layout");

static std::wstring dirOf(const std::wstring& path)
{
    const size_t k = path.find_last_of(L"\\/");
    return k == std::wstring::npos ? std::wstring() : path.substr(0, k);
}

bool ThvClient::Start(const std::wstring& brokerPath, uint32_t slots, uint32_t dataSize, uint32_t openFlags)
{
    Stop();
    if(slots < 1) slots = 1;
    if(slots > THVB_MAX_SLOTS) slots = THVB_MAX_SLOTS;
    dataSize = (dataSize + THVB_PAGE - 1) & ~(THVB_PAGE - 1);
    if(dataSize < THVB_MIN_DATA) dataSize = THVB_MIN_DATA;
    if(dataSize > THVB_MAX_DATA) dataSize = THVB_MAX_DATA;
    if(GetFileAttributesW(brokerPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        mLastError = "thvbridge.exe was not found";
        return false;
    }
    if(!mCsInit)
    {
        InitializeCriticalSection(&mCs);
        mCsInit = true;
    }
    mSlots = slots;
    mData = dataSize;
    mTimeoutMs = 60000;
    mStopping = 0;
    mInflight = 0;

    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};    // inheritable: the broker inherits the section + events
    const uint64_t total = THVB_PAGE + uint64_t(slots) * (THVB_PAGE + dataSize);
    mSection = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, DWORD(total >> 32), DWORD(total), nullptr);
    if(!mSection)
    {
        mLastError = "CreateFileMapping failed";
        return false;
    }
    mView = static_cast<uint8_t*>(MapViewOfFile(mSection, FILE_MAP_ALL_ACCESS, 0, 0, 0));
    if(!mView)
    {
        mLastError = "MapViewOfFile failed";
        CloseHandle(mSection);
        mSection = nullptr;
        return false;
    }
    thvb_shared* sh = Shared();
    sh->magic = THVB_MAGIC;
    sh->proto = THVB_PROTO;
    sh->slot_count = slots;
    sh->slot_data = dataSize;
    sh->state = THVB_STATE_STARTING;
    sh->open_flags = openFlags;

    DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &mParentDup,
                    SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, 0);
    mReady = CreateEventW(&sa, FALSE, FALSE, nullptr);
    sh->parent_process = uint64_t(uintptr_t(mParentDup));
    sh->ready_event = uint64_t(uintptr_t(mReady));

    mReq.assign(slots, nullptr);
    mRsp.assign(slots, nullptr);
    mBusy.assign(slots, 0);
    mRetired.assign(slots, 0);
    mDone.assign(slots, 0);
    mRet.assign(size_t(slots) * 16, 0);
    mOutLen.assign(slots, 0);
    for(uint32_t i = 0; i < slots; i++)
    {
        mReq[i] = CreateEventW(&sa, FALSE, FALSE, nullptr);
        mRsp[i] = CreateEventW(&sa, FALSE, FALSE, nullptr);
        sh->req_event[i] = uint64_t(uintptr_t(mReq[i]));
        sh->rsp_event[i] = uint64_t(uintptr_t(mRsp[i]));
    }
    mFree = CreateSemaphoreW(nullptr, LONG(slots), LONG(slots), nullptr);

    std::wstring cmd = L"\"" + brokerPath + L"\" --section " + std::to_wstring(uint64_t(uintptr_t(mSection)));
    std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
    cmdline.push_back(0);
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    const std::wstring cwd = dirOf(brokerPath);
    if(!CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                       cwd.empty() ? nullptr : cwd.c_str(), &si, &pi))
    {
        mLastError = "could not start thvbridge.exe";
        mDead = false;
        Stop();
        return false;
    }
    CloseHandle(pi.hThread);
    mBroker = pi.hProcess;
    mBrokerPid = pi.dwProcessId;

    HANDLE w[2] = {mReady, mBroker};
    const DWORD r = WaitForMultipleObjects(2, w, FALSE, 30000);
    if(r != WAIT_OBJECT_0)
    {
        mLastError = r == WAIT_OBJECT_0 + 1 ? "thvbridge.exe exited during startup" : "thvbridge.exe did not start in time";
        mDead = false;
        Stop();
        return false;
    }
    if(sh->state != THVB_STATE_READY)
    {
        mLastError = "thvbridge.exe rejected the channel";
        mDead = false;
        Stop();
        return false;
    }
    mDead = false;
    return true;
}

void ThvClient::Stop()
{
    if(mView)
    {
        InterlockedExchange(&mStopping, 1);
        const ULONGLONG t0 = GetTickCount64();
        while(mInflight > 0 && GetTickCount64() - t0 < 5000)
            Sleep(5);
        if(mInflight > 0)
        {
            // a request still in flight: leave the channel mapped rather than pull memory from under a caller
            mLastError = "thvbridge.exe still had requests in flight; the channel was left mapped";
            if(mBroker)
                TerminateProcess(mBroker, 1);
            return;
        }
        if(!mDead && mBroker && WaitForSingleObject(mBroker, 0) == WAIT_TIMEOUT)
        {
            for(uint32_t i = 0; i < mSlots; i++)
                if(!mRetired[i])
                {
                    mTimeoutMs = 2000;
                    Exec(int(i), THVB_CMD_SHUTDOWN);
                    break;
                }
            if(WaitForSingleObject(mBroker, 2000) != WAIT_OBJECT_0)
                TerminateProcess(mBroker, 1);
        }
    }
    mDead = true;
    if(mBroker) { CloseHandle(mBroker); mBroker = nullptr; }
    for(HANDLE h : mReq) if(h) CloseHandle(h);
    for(HANDLE h : mRsp) if(h) CloseHandle(h);
    mReq.clear();
    mRsp.clear();
    if(mReady) { CloseHandle(mReady); mReady = nullptr; }
    if(mParentDup) { CloseHandle(mParentDup); mParentDup = nullptr; }
    if(mFree) { CloseHandle(mFree); mFree = nullptr; }
    if(mView) { UnmapViewOfFile(mView); mView = nullptr; }
    if(mSection) { CloseHandle(mSection); mSection = nullptr; }
    mBrokerPid = 0;
}

bool ThvClient::Alive() const
{
    return mView && !mDead && mBroker && WaitForSingleObject(mBroker, 0) == WAIT_TIMEOUT;
}

thvb_slot* ThvClient::SlotHdr(int slot) const
{
    return reinterpret_cast<thvb_slot*>(mView + THVB_PAGE + size_t(slot) * (THVB_PAGE + mData));
}

uint8_t* ThvClient::SlotData(int slot) const
{
    return mView + THVB_PAGE + size_t(slot) * (THVB_PAGE + mData) + THVB_PAGE;
}

int ThvClient::Acquire()
{
    if(!mView || mDead)
        return -1;
    // counted BEFORE mStopping is looked at: Stop sets mStopping then waits for the count to drain
    InterlockedIncrement(&mInflight);
    if(mStopping || mDead)
    {
        InterlockedDecrement(&mInflight);
        return -1;
    }
    if(WaitForSingleObject(mFree, 60000) != WAIT_OBJECT_0)
    {
        InterlockedDecrement(&mInflight);
        return -1;
    }
    if(mStopping || mDead)
    {
        ReleaseSemaphore(mFree, 1, nullptr);
        InterlockedDecrement(&mInflight);
        return -1;
    }
    EnterCriticalSection(&mCs);
    for(uint32_t i = 0; i < mSlots; i++)
        if(!mBusy[i])
        {
            mBusy[i] = 1;
            LeaveCriticalSection(&mCs);
            return int(i);
        }
    LeaveCriticalSection(&mCs);
    ReleaseSemaphore(mFree, 1, nullptr);   // cannot happen: the semaphore counts free slots
    InterlockedDecrement(&mInflight);
    return -1;
}

void ThvClient::Release(int slot)
{
    if(slot < 0 || uint32_t(slot) >= mSlots)
        return;
    EnterCriticalSection(&mCs);
    const bool retired = mRetired[slot] != 0;
    if(!retired)
        mBusy[slot] = 0;                   // a retired slot stays busy forever (its semaphore count stays taken)
    LeaveCriticalSection(&mCs);
    if(!retired)
        ReleaseSemaphore(mFree, 1, nullptr);
    InterlockedDecrement(&mInflight);
}

uint32_t ThvClient::Exec(int slot, uint32_t cmd, std::initializer_list<uint64_t> args, uint32_t inLen)
{
    if(slot < 0 || uint32_t(slot) >= mSlots)
        return THVB_E_NO_BRIDGE;
    for(int k = 0; k < 16; k++)
        mRet[size_t(slot) * 16 + k] = 0;
    mOutLen[slot] = 0;
    mDone[slot] = 0;
    if(!mView || mDead)
        return THVB_E_NO_BRIDGE;
    thvb_slot* h = SlotHdr(slot);
    h->cmd = cmd;
    h->in_len = inLen;
    h->status = THVB_E_NO_BRIDGE;
    h->out_len = 0;
    int k = 0;
    for(uint64_t a : args)
        if(k < 16)
            h->arg[k++] = a;
    for(; k < 16; k++)
        h->arg[k] = 0;
    const LONG64 s = InterlockedIncrement64(&mSeq);
    h->seq = uint64_t(s);
    MemoryBarrier();
    SetEvent(mReq[slot]);

    HANDLE w[2] = {mRsp[slot], mBroker};
    const ULONGLONG deadline = GetTickCount64() + mTimeoutMs;
    for(;;)
    {
        const ULONGLONG now = GetTickCount64();
        const DWORD left = now < deadline ? DWORD(deadline - now) : 0;
        const DWORD r = WaitForMultipleObjects(2, w, FALSE, left);
        if(r == WAIT_OBJECT_0)
        {
            MemoryBarrier();
            if(h->ret_seq == uint64_t(s))
            {
                for(int j = 0; j < 16; j++)
                    mRet[size_t(slot) * 16 + j] = h->ret[j];
                mOutLen[slot] = h->out_len > mData ? mData : h->out_len;
                mDone[slot] = 1;
                return h->status;
            }
            continue;                      // an answer to an older request on this slot: keep waiting for ours
        }
        if(r == WAIT_OBJECT_0 + 1)
        {
            mDead = true;
            mLastError = "thvbridge.exe exited";
            return THVB_E_NO_BRIDGE;
        }
        break;
    }
    // timed out: the broker may still answer later, over the next user's data -- retire the slot
    EnterCriticalSection(&mCs);
    mRetired[slot] = 1;
    uint32_t retired = 0;
    for(uint32_t i = 0; i < mSlots; i++)
        retired += mRetired[i] ? 1 : 0;
    if(retired >= mSlots)
        mDead = true;
    LeaveCriticalSection(&mCs);
    mLastError = "thvbridge.exe did not answer in time (a channel was retired)";
    return THVB_E_TIMEOUT;
}

uint64_t ThvClient::Ret(int slot, int k) const
{
    if(slot < 0 || uint32_t(slot) >= mSlots || k < 0 || k > 15)
        return 0;
    return mRet[size_t(slot) * 16 + k];
}

uint32_t ThvClient::OutLen(int slot) const
{
    return (slot < 0 || uint32_t(slot) >= mSlots) ? 0 : mOutLen[slot];
}

bool ThvClient::Completed(int slot) const
{
    return slot >= 0 && uint32_t(slot) < mSlots && mDone[slot] != 0;
}

// ---- typed helpers ----

struct SlotGuard                           // Acquire / Release as a scope
{
    ThvClient& c;
    int i;
    explicit SlotGuard(ThvClient& cl) : c(cl), i(cl.Acquire()) {}
    ~SlotGuard() { if(i >= 0) c.Release(i); }
};

uint32_t ThvClient::Ping(uint32_t* brokerPid)
{
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    const uint32_t r = Exec(g.i, THVB_CMD_PING);
    if(brokerPid) *brokerPid = uint32_t(Ret(g.i, 0));
    return r;
}

uint32_t ThvClient::ConnectionInfo(thv_connection_info* ci)
{
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    const uint32_t r = Exec(g.i, THVB_CMD_CONNECTION_INFO);
    if(ci && Completed(g.i)) memcpy(ci, SlotData(g.i), sizeof(*ci));
    return r;
}

uint32_t ThvClient::ProcessInfo(uint64_t pid, thv_process_info* out)
{
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    const uint32_t r = Exec(g.i, THVB_CMD_PROCESS_INFO, {pid});
    if(out && Completed(g.i)) memcpy(out, SlotData(g.i), sizeof(*out));
    return r;
}

uint32_t ThvClient::Read(uint64_t cr3, uint64_t address, void* buffer, size_t size, size_t* done)
{
    size_t got = 0;
    uint32_t r = THV_OK;
    while(got < size)
    {
        SlotGuard g(*this);
        if(g.i < 0) { r = THVB_E_NO_BRIDGE; break; }
        const size_t chunk = (size - got) > mData ? mData : (size - got);
        r = Exec(g.i, THVB_CMD_READ, {cr3, address + got, uint64_t(chunk)});
        const size_t n = Completed(g.i) ? size_t(Ret(g.i, 0)) : 0;
        if(n) memcpy(static_cast<uint8_t*>(buffer) + got, SlotData(g.i), n > chunk ? chunk : n);
        got += n > chunk ? chunk : n;
        if(r != THV_OK || n < chunk) break;
    }
    if(done) *done = got;
    return got == size ? THV_OK : (r == THV_OK ? THV_E_PARTIAL_TRANSFER : r);
}

uint32_t ThvClient::Write(uint64_t cr3, uint64_t address, const void* buffer, size_t size, size_t* done)
{
    size_t put = 0;
    uint32_t r = THV_OK;
    while(put < size)
    {
        SlotGuard g(*this);
        if(g.i < 0) { r = THVB_E_NO_BRIDGE; break; }
        const size_t chunk = (size - put) > mData ? mData : (size - put);
        memcpy(SlotData(g.i), static_cast<const uint8_t*>(buffer) + put, chunk);
        r = Exec(g.i, THVB_CMD_WRITE, {cr3, address + put, uint64_t(chunk)}, uint32_t(chunk));
        const size_t n = Completed(g.i) ? size_t(Ret(g.i, 0)) : 0;
        put += n > chunk ? chunk : n;
        if(r != THV_OK || n < chunk) break;
    }
    if(done) *done = put;
    return put == size ? THV_OK : (r == THV_OK ? THV_E_PARTIAL_TRANSFER : r);
}

// ENUM_* return {count, more, status2, next_index} in ret[0..3]; page until `more` is clear
uint32_t ThvClient::EnumPaged(uint32_t cmd, std::initializer_list<uint64_t> fixedArgs, size_t recSize, std::vector<uint8_t>& out)
{
    out.clear();
    uint64_t start = 0;
    for(int guard = 0; guard < 4096; guard++)
    {
        SlotGuard g(*this);
        if(g.i < 0) return THVB_E_NO_BRIDGE;
        const uint64_t cap = mData / recSize;
        uint64_t a[16] = {};
        size_t n = 0;
        for(uint64_t v : fixedArgs) a[n++] = v;
        a[n++] = start;
        a[n++] = cap;
        const uint32_t r = Exec(g.i, cmd, {a[0], a[1], a[2], a[3]});
        if(!Completed(g.i)) return r;
        const uint64_t count = Ret(g.i, 0), more = Ret(g.i, 1), next = Ret(g.i, 3);
        const size_t bytes = size_t(count > cap ? cap : count) * recSize;
        const uint8_t* d = SlotData(g.i);
        out.insert(out.end(), d, d + bytes);
        if(r != THV_OK) return r;
        if(!more || next <= start) return THV_OK;
        start = next;
    }
    return THV_OK;
}

template<typename T>
static void unpack(const std::vector<uint8_t>& raw, std::vector<T>& out)
{
    out.resize(raw.size() / sizeof(T));
    if(!out.empty()) memcpy(out.data(), raw.data(), out.size() * sizeof(T));
}

uint32_t ThvClient::EnumThreads(uint64_t eprocess, std::vector<thv_thread>& out)
{
    std::vector<uint8_t> raw;
    const uint32_t r = EnumPaged(THVB_CMD_ENUM_THREADS, {eprocess}, sizeof(thv_thread), raw);
    unpack(raw, out);
    return r;
}

uint32_t ThvClient::EnumModules(uint64_t pid, std::vector<thv_module>& out)
{
    std::vector<uint8_t> raw;
    const uint32_t r = EnumPaged(THVB_CMD_ENUM_UMODULES, {pid}, sizeof(thv_module), raw);
    unpack(raw, out);
    return r;
}

uint32_t ThvClient::EnumMemory(uint64_t cr3, std::vector<thv_memory_region>& out)
{
    // ENUM_MEMORY's "start" is an address, and next_index is the address to continue from
    std::vector<uint8_t> raw;
    const uint32_t r = EnumPaged(THVB_CMD_ENUM_MEMORY, {cr3}, sizeof(thv_memory_region), raw);
    unpack(raw, out);
    return r;
}

uint32_t ThvClient::Cr3Query(const thv_cr3_query& q, thv_cr3_result* res)
{
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    memcpy(SlotData(g.i), &q, sizeof(q));
    const uint32_t r = Exec(g.i, THVB_CMD_CR3_QUERY, {}, sizeof(q));
    if(res && Completed(g.i)) memcpy(res, SlotData(g.i), sizeof(*res));
    return r;
}

uint32_t ThvClient::DwatchArm(uint64_t cr3, uint64_t address, uint32_t length, uint32_t kind, uint32_t* id, thv_dwatch_status* st)
{
    if(id) *id = 0;
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    const uint32_t r = Exec(g.i, THVB_CMD_DWATCH_ARM, {cr3, address, length, kind});
    if(Completed(g.i))
    {
        if(st) memcpy(st, SlotData(g.i), sizeof(*st));
        if(id && r == THV_OK) *id = uint32_t(Ret(g.i, 0));
    }
    return r;
}

uint32_t ThvClient::DwatchClear(uint32_t id, thv_dwatch_status* st)
{
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    const uint32_t r = Exec(g.i, THVB_CMD_DWATCH_CLEAR, {id});
    if(st && Completed(g.i)) memcpy(st, SlotData(g.i), sizeof(*st));
    return r;
}

uint32_t ThvClient::DwatchRead(uint32_t id, uint32_t first, std::vector<thv_dwatch_entry>& out, thv_dwatch_status* st)
{
    out.clear();
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    const uint64_t max = (mData - THVB_ARRAY_OFF) / sizeof(thv_dwatch_entry);
    const uint32_t r = Exec(g.i, THVB_CMD_DWATCH_READ, {id, first, max});
    if(!Completed(g.i)) return r;
    if(st) memcpy(st, SlotData(g.i), sizeof(*st));
    uint64_t n = Ret(g.i, 0);
    if(n > max) n = max;
    out.resize(size_t(n));
    if(n) memcpy(out.data(), SlotData(g.i) + THVB_ARRAY_OFF, size_t(n) * sizeof(thv_dwatch_entry));
    return r;
}

uint32_t ThvClient::BreakArm(uint64_t cr3, uint64_t address, uint32_t length, const thv_dwatch_operand* op, uint32_t* id, thv_dwatch_status* st)
{
    if(id) *id = 0;
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    thv_dwatch_operand none = {};
    memcpy(SlotData(g.i), op ? op : &none, sizeof(thv_dwatch_operand));
    const uint32_t r = Exec(g.i, THVB_CMD_DWATCH_ARM_BREAK, {cr3, address, length}, sizeof(thv_dwatch_operand));
    if(Completed(g.i))
    {
        if(st) memcpy(st, SlotData(g.i), sizeof(*st));
        if(id && r == THV_OK) *id = uint32_t(Ret(g.i, 0));
    }
    return r;
}

uint32_t ThvClient::TraceArm(uint64_t cr3, uint64_t address, uint32_t length, uint32_t maxRecords, uint32_t flags, uint32_t* id, thv_dwatch_status* st)
{
    if(id) *id = 0;
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    const uint32_t r = Exec(g.i, THVB_CMD_DWATCH_ARM_TRACE, {cr3, address, length, maxRecords, flags});
    if(Completed(g.i))
    {
        if(st) memcpy(st, SlotData(g.i), sizeof(*st));
        if(id && r == THV_OK) *id = uint32_t(Ret(g.i, 0));
    }
    return r;
}

uint32_t ThvClient::TraceRead(uint32_t id, uint32_t first, uint32_t max, thv_trace_info* info, std::vector<thv_trace_rec>& out, thv_dwatch_status* st)
{
    static_assert(sizeof(thv_trace_rec) == 152 && sizeof(thv_trace_info) == 96, "thv_trace_* layout");
    out.clear();
    if(info) memset(info, 0, sizeof(*info));
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    const uint32_t r = Exec(g.i, THVB_CMD_DWATCH_TR_READ, {id, first, max});
    if(!Completed(g.i)) return r;
    if(st) memcpy(st, SlotData(g.i), sizeof(*st));
    if(info) memcpy(info, SlotData(g.i) + THVB_TRACE_INFO_OFF, sizeof(*info));
    if(r != THV_OK) return r;
    uint64_t n = Ret(g.i, 0);
    if(n > max) n = max;
    const uint64_t room = mData > THVB_ARRAY_OFF ? (mData - THVB_ARRAY_OFF) / sizeof(thv_trace_rec) : 0;
    if(n > room) n = room;
    out.resize(size_t(n));
    if(n) memcpy(out.data(), SlotData(g.i) + THVB_ARRAY_OFF, size_t(n) * sizeof(thv_trace_rec));
    return r;
}

uint32_t ThvClient::BreakRead(uint32_t id, uint32_t index, thv_capture_rec* rec, thv_dwatch_status* st)
{
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    const uint32_t r = Exec(g.i, THVB_CMD_DWATCH_BK_READ, {id, index});
    if(!Completed(g.i)) return r;
    thv_dwatch_status s;
    memcpy(&s, SlotData(g.i), sizeof(s));
    if(st) *st = s;
    if(rec)
    {
        if(r == THV_OK && index < s.count && mData >= THVB_ARRAY_OFF + sizeof(thv_capture_rec))
            memcpy(rec, SlotData(g.i) + THVB_ARRAY_OFF, sizeof(*rec));
        else
            memset(rec, 0, sizeof(*rec));
    }
    return r;
}

uint32_t ThvClient::BreakCmd(uint32_t id, const thv_break_cmd& c, thv_dwatch_status* st)
{
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    memcpy(SlotData(g.i), &c, sizeof(c));
    const uint32_t r = Exec(g.i, THVB_CMD_DWATCH_BK_CMD, {id}, sizeof(c));
    if(st && Completed(g.i)) memcpy(st, SlotData(g.i), sizeof(*st));
    return r;
}

uint32_t ThvClient::FreezeSet(uint64_t cr3, uint64_t userCr3, thv_freeze_status* st)
{
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    const uint32_t r = Exec(g.i, THVB_CMD_FREEZE_SET, {cr3, userCr3});
    if(st && Completed(g.i)) memcpy(st, SlotData(g.i), sizeof(*st));
    return r;
}

uint32_t ThvClient::FreezeRead(uint32_t index, thv_capture_rec* rec, thv_freeze_status* st)
{
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    const uint32_t r = Exec(g.i, THVB_CMD_FREEZE_READ, {index});
    if(!Completed(g.i)) return r;
    thv_freeze_status s;
    memcpy(&s, SlotData(g.i), sizeof(s));
    if(st) *st = s;
    if(rec)
    {
        if(r == THV_OK && index < s.threads && mData >= THVB_ARRAY_OFF + sizeof(thv_capture_rec))
            memcpy(rec, SlotData(g.i) + THVB_ARRAY_OFF, sizeof(*rec));
        else
            memset(rec, 0, sizeof(*rec));
    }
    return r;
}

uint32_t ThvClient::FreezeClear(thv_freeze_status* st)
{
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    const uint32_t r = Exec(g.i, THVB_CMD_FREEZE_CLEAR, {});
    if(st && Completed(g.i)) memcpy(st, SlotData(g.i), sizeof(*st));
    return r;
}

uint32_t ThvClient::CaptureArm(uint64_t cr3, uint64_t address, uint32_t length, const thv_dwatch_operand* op,
                               const thv_capture_cfg& cfg, uint32_t* id, thv_dwatch_status* st)
{
    if(id) *id = 0;
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    uint8_t* d = SlotData(g.i);
    memset(d, 0, THVB_ARRAY_OFF + sizeof(cfg));
    thv_dwatch_operand none = {};
    memcpy(d, op ? op : &none, sizeof(thv_dwatch_operand));
    memcpy(d + THVB_ARRAY_OFF, &cfg, sizeof(cfg));
    const uint32_t r = Exec(g.i, THVB_CMD_DWATCH_ARM_CAPTURE, {cr3, address, length}, uint32_t(THVB_ARRAY_OFF + sizeof(cfg)));
    if(Completed(g.i))
    {
        if(st) memcpy(st, SlotData(g.i), sizeof(*st));
        if(id && r == THV_OK) *id = uint32_t(Ret(g.i, 0));
    }
    return r;
}

uint32_t ThvClient::CapRead(uint32_t id, uint32_t index, thv_capture_rec* rec, thv_dwatch_status* st)
{
    SlotGuard g(*this);
    if(g.i < 0) return THVB_E_NO_BRIDGE;
    const uint32_t r = Exec(g.i, THVB_CMD_DWATCH_CAP_READ, {id, index});
    if(!Completed(g.i)) return r;
    thv_dwatch_status s;
    memcpy(&s, SlotData(g.i), sizeof(s));
    if(st) *st = s;
    if(rec)
    {
        if(r == THV_OK && index < s.count && mData >= THVB_ARRAY_OFF + sizeof(thv_capture_rec))
            memcpy(rec, SlotData(g.i) + THVB_ARRAY_OFF, sizeof(*rec));
        else
            memset(rec, 0, sizeof(*rec));
    }
    return r;
}
