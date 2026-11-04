// thvclient.h -- the C++ client for thvbridge.exe (the trusted broker between an untrusted tool and turing-hv).
//
// x64dbg can't be a trusted hypervisor caller (it loads plugins and its script engine generates code), so -- exactly
// like Cheat Engine -- it never talks to turinghv.dll. It creates an unnamed shared section + events, starts
// thvbridge.exe with the section handle, and puts requests in slots. This mirrors Cheat Engine's turinghvbridge.pas
// byte for byte; the wire format is vendor/thvbridge_proto.h.
#pragma once
#ifndef TURINGHV_STATIC
#define TURINGHV_STATIC 1      // turinghv.h for its types only: we never link turinghv.dll
#endif
#include <windows.h>
#include <stdint.h>
#include <string>
#include <vector>
#include "vendor/thvbridge_proto.h"

// client-side errors (high bit set, never a hypervisor status)
#define THVB_E_NO_BRIDGE 0xC0000001u
#define THVB_E_TIMEOUT   0xC0000002u

class ThvClient
{
public:
    ThvClient() = default;
    ~ThvClient() { Stop(); }
    ThvClient(const ThvClient&) = delete;
    ThvClient& operator=(const ThvClient&) = delete;

    // start thvbridge.exe at `brokerPath`; true when the broker reached THVB_STATE_READY (the session may still have
    // been refused by the caller gate -- OpenStatus() says how)
    bool Start(const std::wstring& brokerPath, uint32_t slots = 4, uint32_t dataSize = 1u << 20, uint32_t openFlags = 0);
    void Stop();
    bool Alive() const;
    const std::string& LastError() const { return mLastError; }

    uint32_t OpenStatus() const { return mView ? Shared()->open_status : THVB_E_NO_BRIDGE; }
    uint32_t BrokerSdkVersion() const { return mView ? Shared()->sdk_api_version : 0; }
    uint32_t BrokerPid() const { return mBrokerPid; }

    // ---- one request: Acquire a slot, fill SlotData, Exec, read Ret/OutLen/SlotData, Release ----
    int Acquire();
    void Release(int slot);
    uint8_t* SlotData(int slot) const;
    uint32_t SlotCapacity() const { return mData; }
    uint32_t Exec(int slot, uint32_t cmd, std::initializer_list<uint64_t> args = {}, uint32_t inLen = 0);
    uint64_t Ret(int slot, int k) const;
    uint32_t OutLen(int slot) const;
    bool Completed(int slot) const;

    // ---- typed helpers (each does its own Acquire / Release) ----
    uint32_t Ping(uint32_t* brokerPid);
    uint32_t ConnectionInfo(thv_connection_info* ci);
    uint32_t ProcessInfo(uint64_t pid, thv_process_info* out);
    uint32_t Read(uint64_t cr3, uint64_t address, void* buffer, size_t size, size_t* done);
    uint32_t Write(uint64_t cr3, uint64_t address, const void* buffer, size_t size, size_t* done);
    uint32_t EnumThreads(uint64_t eprocess, std::vector<thv_thread>& out);
    uint32_t EnumModules(uint64_t pid, std::vector<thv_module>& out);
    uint32_t EnumMemory(uint64_t cr3, std::vector<thv_memory_region>& out);
    uint32_t Cr3Query(const thv_cr3_query& q, thv_cr3_result* r);
    // the rev146b data watch / rev148 capture / rev149 parking breakpoint
    uint32_t DwatchArm(uint64_t cr3, uint64_t address, uint32_t length, uint32_t kind, uint32_t* id, thv_dwatch_status* st);
    uint32_t DwatchClear(uint32_t id, thv_dwatch_status* st);
    uint32_t DwatchRead(uint32_t id, uint32_t first, std::vector<thv_dwatch_entry>& out, thv_dwatch_status* st);
    uint32_t BreakArm(uint64_t cr3, uint64_t address, uint32_t length, const thv_dwatch_operand* op, uint32_t* id, thv_dwatch_status* st);
    uint32_t BreakRead(uint32_t id, uint32_t index, thv_capture_rec* rec, thv_dwatch_status* st);
    uint32_t BreakCmd(uint32_t id, const thv_break_cmd& c, thv_dwatch_status* st);
    uint32_t CaptureArm(uint64_t cr3, uint64_t address, uint32_t length, const thv_dwatch_operand* op, const thv_capture_cfg& cfg, uint32_t* id, thv_dwatch_status* st);
    uint32_t CapRead(uint32_t id, uint32_t index, thv_capture_rec* rec, thv_dwatch_status* st);
    // rev150: the native trace -- the first thread to reach `address` is followed instruction by instruction, never stopped
    uint32_t TraceArm(uint64_t cr3, uint64_t address, uint32_t length, uint32_t maxRecords, uint32_t flags, uint32_t* id, thv_dwatch_status* st);
    // records [first, first + out.size()) (at most `max`); *info = its state; st->entries = records taken so far
    uint32_t TraceRead(uint32_t id, uint32_t first, uint32_t max, thv_trace_info* info, std::vector<thv_trace_rec>& out, thv_dwatch_status* st);

private:
    thvb_shared* Shared() const { return reinterpret_cast<thvb_shared*>(mView); }
    thvb_slot* SlotHdr(int slot) const;
    uint32_t EnumPaged(uint32_t cmd, std::initializer_list<uint64_t> fixedArgs, size_t recSize, std::vector<uint8_t>& out);

    HANDLE mSection = nullptr;
    uint8_t* mView = nullptr;
    HANDLE mBroker = nullptr;
    HANDLE mReady = nullptr;
    HANDLE mParentDup = nullptr;
    HANDLE mFree = nullptr;                // a semaphore counting free slots
    uint32_t mBrokerPid = 0;
    uint32_t mSlots = 0;
    uint32_t mData = 0;
    DWORD mTimeoutMs = 60000;
    std::vector<HANDLE> mReq, mRsp;
    std::vector<uint8_t> mBusy, mRetired, mDone;
    std::vector<uint64_t> mRet;
    std::vector<uint32_t> mOutLen;
    CRITICAL_SECTION mCs;
    bool mCsInit = false;
    volatile LONG64 mSeq = 0;
    volatile LONG mInflight = 0;
    volatile LONG mStopping = 0;
    bool mDead = true;
    std::string mLastError;
};
