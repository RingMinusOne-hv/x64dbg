// thvclient_selftest -- drives the real thvbridge.exe through ThvClient: start, ping, connection info, the gate's
// verdict, and (if the session was granted and a pid is given) process info + a read of the target's PE header.
//   thvclient_selftest.exe <path\to\thvbridge.exe> [pid]
#include "../thvclient.h"
#include <cstdio>
#include <cstdlib>

int wmain(int argc, wchar_t** argv)
{
    if(argc < 2)
    {
        fwprintf(stderr, L"usage: %ls <thvbridge.exe> [pid]\n", argv[0]);
        return 2;
    }
    ThvClient c;
    if(!c.Start(argv[1]))
    {
        printf("FAIL start: %s\n", c.LastError().c_str());
        return 1;
    }
    printf("broker pid %u, broker sdk %08x, open_status %u\n", c.BrokerPid(), c.BrokerSdkVersion(), c.OpenStatus());
    uint32_t bp = 0;
    const uint32_t pr = c.Ping(&bp);
    printf("ping: status %u, broker pid %u %s\n", pr, bp, (pr == THV_OK && bp == c.BrokerPid()) ? "(ok)" : "(MISMATCH)");
    thv_connection_info ci = {};
    const uint32_t cr = c.ConnectionInfo(&ci);
    printf("connection: status %u, client api %08x, hypervisor abi %08x\n", cr, ci.client_api_version, ci.hypervisor_abi_version);
    int rc = (pr == THV_OK && bp == c.BrokerPid()) ? 0 : 1;
    if(argc >= 3 && c.OpenStatus() == THV_OK)
    {
        const uint64_t pid = _wcstoui64(argv[2], nullptr, 10);
        thv_process_info pi = {};
        const uint32_t ir = c.ProcessInfo(pid, &pi);
        printf("process %llu: status %u, name %.16s, dirbase %016llx, image %016llx\n", (unsigned long long)pid, ir, pi.name,
               (unsigned long long)pi.dirbase, (unsigned long long)pi.image_base);
        if(ir == THV_OK && pi.dirbase && pi.image_base)
        {
            unsigned char mz[2] = {};
            size_t done = 0;
            const uint32_t rr = c.Read(pi.dirbase, pi.image_base, mz, 2, &done);
            printf("read image header: status %u, %zu bytes, '%c%c'\n", rr, done, mz[0] ? mz[0] : '?', mz[1] ? mz[1] : '?');
            if(rr != THV_OK || mz[0] != 'M' || mz[1] != 'Z')
                rc = 1;
        }
    }
    else if(argc >= 3)
    {
        printf("(session not granted by the caller gate -- open_status %u -- skipping the process read)\n", c.OpenStatus());
    }
    c.Stop();
    printf(rc == 0 ? "thvclient_selftest: PASS\n" : "thvclient_selftest: FAIL\n");
    return rc;
}
