#ifndef MINHOOK_BUFFER_NATIVE_H
#define MINHOOK_BUFFER_NATIVE_H

#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif

#include <winternl.h>
#include <sysinfoapi.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(status)	((NTSTATUS) (status) >= 0)
#endif

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)((LONG64)(-1)))
#endif

NTSYSCALLAPI
NTSTATUS
NTAPI
NtFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
);

static inline BOOL NtVirtualFree(LPVOID addr, SIZE_T size, DWORD type) {
  return NT_SUCCESS(NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, type));
}

typedef enum _MEMORY_INFORMATION_CLASS {
  MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
  MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
  MemoryMappedFilenameInformation, // UNICODE_STRING
  MemoryRegionInformation, // MEMORY_REGION_INFORMATION
  MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
  MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
  MemoryImageInformation, // MEMORY_IMAGE_INFORMATION
  MemoryRegionInformationEx,
  MemoryPrivilegedBasicInformation,
  MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
  MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

static inline SIZE_T NtVirtualQuery(PVOID addr, PMEMORY_BASIC_INFORMATION info, SIZE_T len) {
  SIZE_T ret;

  return NT_SUCCESS(NtQueryVirtualMemory(
      NtCurrentProcess(), addr, MemoryBasicInformation, info, len, &ret)) ? ret : 0;
}

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);

static inline LPVOID NtVirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD protect) {
  LPVOID ret = addr;
  return NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess(), &ret, 0, &size, type, protect)) ? ret : NULL;
}

NTSYSCALLAPI
NTSTATUS
NTAPI
NtProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);
NTSYSCALLAPI
NTSTATUS
NTAPI
NtFlushInstructionCache(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ SIZE_T Length
);

static inline VOID WINAPI MinGetSystemInfo(LPSYSTEM_INFO si) {
  SYSTEM_BASIC_INFORMATION info;
  if (!NT_SUCCESS(NtQuerySystemInformation(SystemBasicInformation, &info, sizeof(info), NULL))) {
    return;
  }
  // only this is used by min-hook
  si->lpMinimumApplicationAddress = (LPVOID) info.LowestUserAddress;
  si->lpMaximumApplicationAddress = (LPVOID) info.HighestUserAddress;
  si->dwAllocationGranularity = info.AllocationGranularity;
}

#define RtlCreateDefaultHeap() RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL)

NTSYSAPI
PVOID
NTAPI
RtlReAllocateHeap(
    _In_ PVOID HeapHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Size
);

#ifdef __cplusplus
}
#endif


#endif //MINHOOK_BUFFER_NATIVE_H
