#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <DbgHelp.h>

#pragma comment(lib, "Dbghelp.lib")

#define COOKIE 0xA5C39E7D51B20F46ULL

typedef struct JOB {
    uint64_t encoded_payload;
    uint64_t expected_payload;
    uint64_t seed;
    uint32_t length;
    uint32_t marker;
} JOB;

static JOB active_job;
static volatile uint64_t audit_sink;
static const char *dump_path;

__declspec(noinline) uint64_t audit_payload(const JOB *job) {
    const unsigned char *payload = (const unsigned char *)(uintptr_t)(job->encoded_payload ^ COOKIE);
    uint64_t result = job->seed;
    unsigned i;
    for (i = 0; i < job->length; ++i) result = result * 131 + payload[i];
    return result;
}

__declspec(noinline) uint64_t consume_payload(const JOB *job, const unsigned char *payload) {
    volatile uint64_t local = job->seed;
    local ^= payload[3];
    return local + payload[7];
}

__declspec(noinline) uint64_t resolve_payload(const JOB *job) {
    uint64_t decoded = job->encoded_payload ^ COOKIE;
#ifdef FIXED_POINTER
    uintptr_t narrowed = (uintptr_t)decoded;
#else
    uint32_t narrowed = (uint32_t)decoded; /* defect: truncates an x64 pointer */
#endif
    const unsigned char *payload = (const unsigned char *)(uintptr_t)narrowed;
    uint64_t result = consume_payload(job, payload);
    audit_sink = result;
    return result + 7;
}

__declspec(noinline) uint64_t dispatch_job(const JOB *job) {
    uint64_t result = resolve_payload(job);
    audit_sink = result ^ job->marker;
    return result ^ job->seed;
}

static int write_dump(EXCEPTION_POINTERS *pointers) {
    HANDLE file = CreateFileA(dump_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    MINIDUMP_EXCEPTION_INFORMATION info;
    BOOL okay;
    if (file == INVALID_HANDLE_VALUE) return EXCEPTION_EXECUTE_HANDLER;
    info.ThreadId = GetCurrentThreadId();
    info.ExceptionPointers = pointers;
    info.ClientPointers = FALSE;
    okay = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), file,
                            MiniDumpWithDataSegs | MiniDumpWithPrivateReadWriteMemory |
                            MiniDumpWithThreadInfo, &info, NULL, NULL);
    CloseHandle(file);
    printf("dump=%d exception=%08lX address=%p fault=%p mode=%llu expected=%p\n",
           okay ? 1 : 0, pointers->ExceptionRecord->ExceptionCode,
           pointers->ExceptionRecord->ExceptionAddress,
           (void *)(uintptr_t)pointers->ExceptionRecord->ExceptionInformation[1],
           (unsigned long long)pointers->ExceptionRecord->ExceptionInformation[0],
           (void *)(uintptr_t)active_job.expected_payload);
    return EXCEPTION_EXECUTE_HANDLER;
}

int main(int argc, char **argv) {
    unsigned char *payload;
    uint64_t result = 0;
    unsigned i;
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    if (argc != 2) return 2;
    dump_path = argv[1];
    payload = (unsigned char *)VirtualAlloc((void *)(uintptr_t)0x000001D47A200000ULL,
                                             0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!payload) return 3;
    for (i = 0; i < 32; ++i) payload[i] = (unsigned char)(i * 17 + 3);
    active_job.encoded_payload = ((uint64_t)(uintptr_t)payload) ^ COOKIE;
    active_job.expected_payload = (uint64_t)(uintptr_t)payload;
    active_job.seed = 0x39B74A1ED5C2608FULL;
    active_job.length = 32;
    active_job.marker = 0xC0DEC0DE;
    audit_sink = audit_payload(&active_job);
    __try {
        result = dispatch_job(&active_job);
    } __except (write_dump(GetExceptionInformation())) {
        if (result) return 4;
    }
#ifdef PRINT_RESULT
    printf("result=%016llX\n", (unsigned long long)result);
#endif
    return 0;
}
