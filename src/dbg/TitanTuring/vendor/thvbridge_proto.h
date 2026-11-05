/*
 * thvbridge_proto.h -- the wire format between Cheat Engine and thvbridge.exe.
 *
 * WHY A BRIDGE.  turing-hv serves memory only to an elevated program whose code it measured and that holds no
 * foreign or generated code (the caller gate).  Cheat Engine cannot be that program: its executable alone is
 * ~2000 code pages (the operator list holds 4096 over every program), it loads its own DLLs (lua, plugins) and its
 * Lua engine can generate code.  thvbridge.exe is tiny, links only turinghv.dll and Windows, and does nothing but
 * hand Cheat Engine's requests to the SDK.  It is deliberately DUMB: every policy (which CR3, how to walk a PEB, how
 * to cache regions) lives in Cheat Engine, so the broker -- whose every rebuild must be re-trusted -- rarely changes.
 *
 * TRANSPORT.  Cheat Engine creates, unnamed and inheritable: one shared section, one request and one response event
 * per slot, a duplicate of its own process handle and a ready event.  It writes the handle values into the section
 * header, starts thvbridge.exe with the section handle on the command line, and the broker inherits the rest.
 * Nothing is named, so no other process can find the broker's channel.
 *
 *   [ thvb_shared header : 4096 bytes ]
 *   [ slot 0 header      : 4096 bytes ][ slot 0 data : slot_data bytes ]
 *   [ slot 1 header ...                                                 ]
 *
 * A request: Cheat Engine owns a slot (its own lock), fills cmd/args/in_len/data, sets req_event[i] and waits on
 * rsp_event[i] (and the broker's process).  The broker copies the header out before looking at it, checks every
 * length and offset against slot_data, runs the SDK call with buffers INSIDE that slot's data area only, writes
 * status/ret/out_len and sets rsp_event[i].  The broker never puts one of its own pointers into the section.
 *
 * All fields little-endian, naturally aligned; the Pascal mirror is turinghvbridge.pas.
 */
#ifndef THVBRIDGE_PROTO_H
#define THVBRIDGE_PROTO_H

#include <stdint.h>
#include "turinghv.h"

#define THVB_MAGIC        0x42564854u   /* 'THVB' */
#define THVB_PROTO        1u
#define THVB_MAX_SLOTS    64u
#define THVB_PAGE         4096u
#define THVB_MIN_DATA     (64u * 1024u)
#define THVB_MAX_DATA     (16u * 1024u * 1024u)
#define THVB_ARRAY_OFF    512u          /* where an array starts when a fixed struct precedes it in data[] */

/* thvb_shared.state */
#define THVB_STATE_STARTING 0
#define THVB_STATE_READY    1           /* thv_open answered (open_status says how; the session may still be refused) */
#define THVB_STATE_FAILED   (-1)        /* the header was malformed: the broker exits */

typedef struct thvb_shared {
    uint32_t magic;                     /*    0  THVB_MAGIC (CE)                                         */
    uint32_t proto;                     /*    4  THVB_PROTO (CE)                                         */
    uint32_t slot_count;                /*    8  1..THVB_MAX_SLOTS (CE)                                  */
    uint32_t slot_data;                 /*   12  bytes of data per slot, multiple of 4096 (CE)            */
    volatile int32_t state;             /*   16  THVB_STATE_* (broker)                                    */
    uint32_t open_status;               /*   20  what thv_open answered (broker)                          */
    uint32_t broker_pid;                /*   24  (broker)                                                 */
    uint32_t open_flags;                /*   28  thv_open flags to use (CE)                               */
    uint64_t parent_process;            /*   32  inherited, SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION   */
    uint64_t ready_event;               /*   40  inherited; the broker sets it once state is final        */
    uint64_t req_event[THVB_MAX_SLOTS]; /*   48  inherited auto-reset events                              */
    uint64_t rsp_event[THVB_MAX_SLOTS]; /*  560                                                           */
    thv_connection_info conn;           /* 1072  (broker, after thv_open)                                 */
    thv_access access;                  /* 1088  (broker, after thv_open) 288 bytes                       */
    char     version[32];               /* 1376  the broker's build                                       */
    uint32_t sdk_api_version;           /* 1408  THV_CLIENT_API_VERSION the broker was built against      */
    uint32_t reserved0;                 /* 1412                                                           */
} thvb_shared;

typedef struct thvb_slot {
    uint32_t cmd;                       /*    0  THVB_CMD_* (CE)                                          */
    uint32_t status;                    /*    4  thv status of the call (broker)                          */
    uint32_t in_len;                    /*    8  input bytes in data[] (CE)                               */
    uint32_t out_len;                   /*   12  output bytes in data[] (broker)                          */
    uint64_t seq;                       /*   16  echoed in ret_seq                                        */
    uint64_t arg[16];                   /*   24  (CE)                                                     */
    uint64_t ret[16];                   /*  152  (broker)                                                 */
    uint64_t ret_seq;                   /*  280  (broker)                                                 */
} thvb_slot;

/* Scatter/gather descriptor for THVB_CMD_READ_SCATTER / WRITE_SCATTER (in data[] at offset 0). */
typedef struct thvb_xfer {
    uint64_t cr3;
    uint64_t address;
    uint32_t size;
    uint32_t done;                      /* (broker) bytes moved, a contiguous prefix                      */
    uint32_t data_off;                  /* where in data[] the bytes are (write) / go (read)              */
    uint32_t reserved;
} thvb_xfer;
#define THVB_SCATTER_MAX 1024u

/*
 * Commands.  "ret: e" means ret[0..3] = thv_enum_info {count, more, status2, next_index}.
 * Arrays are written to data[] at offset 0 unless a fixed struct precedes them (then at THVB_ARRAY_OFF).
 */
enum thvb_cmd {
    THVB_CMD_PING              = 1,     /* ret0 = broker pid, ret1 = THVB_PROTO                                   */
    THVB_CMD_CONNECTION_INFO   = 2,     /* out: thv_connection_info                                               */
    THVB_CMD_GET_ACCESS        = 3,     /* out: thv_access (status of the call is thv_get_access's)               */
    THVB_CMD_REOPEN            = 4,     /* arg0 = open flags: thv_close + thv_open; out: thv_connection_info       */
    THVB_CMD_STATUS            = 5,     /* out: thv_hypervisor_status                                             */
    THVB_CMD_INTRO_DIAG        = 6,     /* out: thv_intro_diagnostics                                             */
    THVB_CMD_PROCESS_INFO      = 7,     /* arg0 = pid; out: thv_process_info                                      */
    THVB_CMD_READ              = 8,     /* arg0 cr3, arg1 address, arg2 size (<= slot_data); out: bytes; ret0 done */
    THVB_CMD_WRITE             = 9,     /* arg0 cr3, arg1 address, arg2 size; in: bytes; ret0 done                */
    THVB_CMD_READ_PHYS         = 10,    /* arg0 physical address, arg1 size; out: bytes; ret0 done                */
    THVB_CMD_READ_SCATTER      = 11,    /* arg0 count; in: thvb_xfer[count]; out: same with done; ret0 total      */
    THVB_CMD_WRITE_SCATTER     = 12,    /* arg0 count; in: thvb_xfer[count] + bytes; out: thvb_xfer[]; ret0 total */
    THVB_CMD_READ_PHYS_SCATTER = 13,    /* like READ_SCATTER, address physical, cr3 ignored                       */
    THVB_CMD_ENUM_PROCESSES    = 14,    /* arg0 start, arg1 capacity; out: thv_process[]; ret: e                   */
    THVB_CMD_ENUM_KMODULES     = 15,    /* arg0 start, arg1 capacity; out: thv_module[]; ret: e                    */
    THVB_CMD_ENUM_UMODULES     = 16,    /* arg0 pid, arg1 start, arg2 capacity; out: thv_module[]; ret: e          */
    THVB_CMD_ENUM_THREADS      = 17,    /* arg0 eprocess, arg1 start, arg2 capacity; out: thv_thread[]; ret: e     */
    THVB_CMD_ENUM_MEMORY       = 18,    /* arg0 cr3, arg1 start address, arg2 capacity; out: region[]; ret: e      */
    THVB_CMD_PHYS_RANGES       = 19,    /* arg0 capacity; out: thv_physical_range[]; ret: e                        */
    THVB_CMD_CR3_QUERY         = 20,    /* in: thv_cr3_query; out: thv_cr3_result                                  */
    THVB_CMD_CR3_WATCH         = 21,    /* arg0 pid; out: thv_cr3_watch_result                                     */
    THVB_CMD_CR3_SCAN_STEP     = 22,    /* in: thv_cr3_scan; out: thv_cr3_scan_result                              */
    THVB_CMD_XWATCH_ARM        = 23,    /* arg0 cr3, arg1 address, arg2 length, arg3 flags; out: thv_xwatch_status */
    THVB_CMD_XWATCH_ARM_DEREF  = 24,    /* + arg4 reg, arg5 off1, arg6 off2, arg7 bytes; out: thv_xwatch_status    */
    THVB_CMD_XWATCH_READ       = 25,    /* arg0 from, arg1 max; out: status, hits thv_watch_hit[] @ARRAY_OFF        */
    THVB_CMD_XWATCH_CLEAR      = 26,    /* out: thv_xwatch_status                                                  */
    THVB_CMD_WWATCH_ARM        = 27,    /* arg0 cr3, arg1 address, arg2 length, arg3 flags, arg4 cap;
                                           out: status, uint64 pages[] @ARRAY_OFF                                  */
    THVB_CMD_WWATCH_READ       = 28,    /* arg0 from, arg1 max; out: status, thv_watch_hit[] @ARRAY_OFF             */
    THVB_CMD_WWATCH_CLEAR      = 29,    /* out: thv_xwatch_status                                                  */
    THVB_CMD_SLAT_QUERY        = 30,    /* arg0 cr3, arg1 address, arg2 pages; out: thv_slat_page[]; ret0 slat      */
    THVB_CMD_LOG_READ          = 31,    /* arg0 from, arg1 max; out: thv_log_info, bytes @ARRAY_OFF; ret0 got       */
    THVB_CMD_TRUST_QUERY       = 32,    /* out: thv_trust_list (read only: the broker never asks for trust)         */
    THVB_CMD_SHUTDOWN          = 33,    /* the broker exits after answering                                        */
    /* turing-hv rev146b (SDK 1.8): the data watch -- "find out what writes / accesses this address" */
    THVB_CMD_DWATCH_ARM        = 34,    /* arg0 cr3, arg1 address, arg2 length, arg3 kind; out: thv_dwatch_status;
                                           ret0 id                                                                  */
    THVB_CMD_DWATCH_READ       = 35,    /* arg0 id, arg1 first, arg2 max; out: status, thv_dwatch_entry[] @ARRAY_OFF */
    THVB_CMD_DWATCH_CLEAR      = 36,    /* arg0 id (0 = all); out: thv_dwatch_status                                */
    /* turing-hv rev147 (SDK 1.9): the instruction watch -- "find out what addresses this instruction accesses" */
    THVB_CMD_DWATCH_ARM_EXEC   = 37,    /* arg0 cr3, arg1 instruction, arg2 its length, arg3 flags (rev147b:
                                           THV_DWATCH_HARD or 0); in: thv_dwatch_operand; out: thv_dwatch_status;
                                           ret0 id                                                                  */
    /* turing-hv rev148 (SDK 1.11): the capture breakpoint -- snapshot every value at an instruction, then disarm */
    THVB_CMD_DWATCH_ARM_CAPTURE = 38,   /* arg0 cr3, arg1 instruction, arg2 length; in: thv_dwatch_operand @0 +
                                           thv_capture_cfg @THVB_ARRAY_OFF; out: thv_dwatch_status; ret0 id          */
    THVB_CMD_DWATCH_CAP_READ    = 39,   /* arg0 id, arg1 index; out: thv_dwatch_status @0, thv_capture_rec @ARRAY_OFF */
    /* turing-hv rev149 (SDK 1.12): the parking breakpoint -- stop a thread at an instruction, step / continue it */
    THVB_CMD_DWATCH_ARM_BREAK   = 40,   /* arg0 cr3, arg1 instruction, arg2 length; in: thv_dwatch_operand @0;
                                           out: thv_dwatch_status; ret0 id                                          */
    THVB_CMD_DWATCH_BK_READ     = 41,   /* arg0 id, arg1 index; out: thv_dwatch_status @0, thv_capture_rec @ARRAY_OFF */
    THVB_CMD_DWATCH_BK_CMD      = 42,   /* arg0 id; in: thv_break_cmd @0; out: thv_dwatch_status                      */
    /* turing-hv rev150 (SDK 1.13): the native trace -- follow a thread instruction by instruction, it never stops */
    THVB_CMD_DWATCH_ARM_TRACE   = 43,   /* arg0 cr3, arg1 instruction, arg2 length, arg3 max records (0 = 1000),
                                           arg4 flags (THV_TRF_OVER or 0); out: thv_dwatch_status; ret0 id          */
    THVB_CMD_DWATCH_TR_READ     = 44,   /* arg0 id, arg1 first, arg2 max; out: thv_dwatch_status @0, thv_trace_info
                                           @THVB_TRACE_INFO_OFF, thv_trace_rec[] @ARRAY_OFF; ret0 records copied     */
    /* turing-hv rev151 (SDK 1.14): the freeze -- every user thread of one process held, invisibly. Never the broker's
       own process or the one that started it (Cheat Engine / x64dbg would freeze itself) */
    THVB_CMD_FREEZE_SET         = 45,   /* arg0 cr3, arg1 user cr3 (0 = none); out: thv_freeze_status                 */
    THVB_CMD_FREEZE_READ        = 46,   /* arg0 index; out: thv_freeze_status @0, thv_capture_rec @ARRAY_OFF;
                                           ret0 threads (keeps the freeze alive)                                    */
    THVB_CMD_FREEZE_CLEAR       = 47    /* out: thv_freeze_status                                                    */
};
#define THVB_TRACE_INFO_OFF 128u        /* THVB_CMD_DWATCH_TR_READ: where thv_trace_info sits in data[] */

#endif
