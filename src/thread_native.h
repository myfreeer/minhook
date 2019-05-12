#ifndef MINHOOK_THREAD_NATIVE_H
#define MINHOOK_THREAD_NATIVE_H

#include "buffer_native.h"

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001)
#endif

typedef struct _SYSTEM_THREAD_INFORMATION {
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER CreateTime;
  ULONG WaitTime;
  PVOID StartAddress;
  CLIENT_ID ClientId;
  KPRIORITY Priority;
  LONG BasePriority;
  ULONG ContextSwitches;
  ULONG ThreadState;
  KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION_EX {
  ULONG NextEntryOffset;
  ULONG NumberOfThreads;
  LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
  ULONG HardFaultCount; // since WIN7
  ULONG NumberOfThreadsHighWatermark; // since WIN7
  ULONGLONG CycleTime; // since WIN7
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ImageName;
  KPRIORITY BasePriority;
  HANDLE UniqueProcessId;
  HANDLE InheritedFromUniqueProcessId;
  ULONG HandleCount;
  ULONG SessionId;
  ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
  SIZE_T PeakVirtualSize;
  SIZE_T VirtualSize;
  ULONG PageFaultCount;
  SIZE_T PeakWorkingSetSize;
  SIZE_T WorkingSetSize;
  SIZE_T QuotaPeakPagedPoolUsage;
  SIZE_T QuotaPagedPoolUsage;
  SIZE_T QuotaPeakNonPagedPoolUsage;
  SIZE_T QuotaNonPagedPoolUsage;
  SIZE_T PagefileUsage;
  SIZE_T PeakPagefileUsage;
  SIZE_T PrivatePageCount;
  LARGE_INTEGER ReadOperationCount;
  LARGE_INTEGER WriteOperationCount;
  LARGE_INTEGER OtherOperationCount;
  LARGE_INTEGER ReadTransferCount;
  LARGE_INTEGER WriteTransferCount;
  LARGE_INTEGER OtherTransferCount;
  SYSTEM_THREAD_INFORMATION Threads[1]; // SystemProcessInformation
  // SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1]; // SystemExtendedProcessinformation
  // SYSTEM_EXTENDED_THREAD_INFORMATION + SYSTEM_PROCESS_INFORMATION_EXTENSION // SystemFullProcessInformation
} SYSTEM_PROCESS_INFORMATION_EX, *PSYSTEM_PROCESS_INFORMATION_EX;
typedef struct _NT_TEB {
  NT_TIB NtTib;

  PVOID EnvironmentPointer;
  CLIENT_ID ClientId;
  PVOID ActiveRpcHandle;
  PVOID ThreadLocalStoragePointer;
} NT_TEB, *PNT_TEB;

#define NtGetCurrentProcessId() (((PNT_TEB)NtCurrentTeb())->ClientId.UniqueProcess)
#define NtGetCurrentThreadId() (((PNT_TEB)NtCurrentTeb())->ClientId.UniqueThread)

// Suspended threads for Freeze()/Unfreeze().
typedef struct _FROZEN_THREADS {
  LPDWORD pItems;         // Data heap
  UINT capacity;       // Size of allocated data heap, items
  UINT size;           // Actual number of data items
} FROZEN_THREADS, *PFROZEN_THREADS;


NTSTATUS EnumerateThreads(PVOID heap, PFROZEN_THREADS threads) {
  if (!heap || !threads) {
    return STATUS_UNSUCCESSFUL;
  }
  SIZE_T bufferSize = 0;
  ULONG requiredBufferSize = 0;
  NTSTATUS status;
  void *processInfoBuffer = NULL;

  // get SystemProcessInformation
  for (;;) {
    bufferSize += 0x10000;
    requiredBufferSize = (ULONG) bufferSize;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &processInfoBuffer, 0, &bufferSize,
                                     MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
      processInfoBuffer = NULL;
      break;
    }

    status = NtQuerySystemInformation(SystemProcessInformation, processInfoBuffer,
                                      bufferSize, &requiredBufferSize);

    if (status == STATUS_INFO_LENGTH_MISMATCH) {
      NtFreeVirtualMemory(NtCurrentProcess(), processInfoBuffer, &bufferSize, MEM_RELEASE);
      processInfoBuffer = NULL;
      bufferSize = (SIZE_T) requiredBufferSize;
    } else {
      break;
    }
  }
  if (processInfoBuffer == NULL) {
    return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
  }

  // get SystemProcessInformation of current process
  PSYSTEM_PROCESS_INFORMATION_EX processInfo = processInfoBuffer;
  PSYSTEM_PROCESS_INFORMATION_EX currentProcessInfo = NULL;
  HANDLE currentProcessId = NtGetCurrentProcessId();
  ULONG_PTR offset = 0;
  do {
    processInfo = (PSYSTEM_PROCESS_INFORMATION_EX) ((ULONG_PTR) processInfo + offset);
    if (processInfo->UniqueProcessId == currentProcessId) {
      currentProcessInfo = processInfo;
      break;
    }
  } while ((offset = processInfo->NextEntryOffset) != 0);
  if (currentProcessInfo == NULL) {
    NtFreeVirtualMemory(NtCurrentProcess(), processInfoBuffer, &bufferSize, MEM_RELEASE);
    // Probably STATUS_NOT_FOUND is better here.
    return STATUS_UNSUCCESSFUL;
  }

  // get info of threads
  PDWORD threadIdBuffer = RtlAllocateHeap(heap, 0, currentProcessInfo->NumberOfThreads * sizeof(DWORD));
  if (threadIdBuffer == NULL) {
    NtFreeVirtualMemory(NtCurrentProcess(), processInfoBuffer, &bufferSize, MEM_RELEASE);
    return STATUS_UNSUCCESSFUL;
  }
  unsigned threadIdBufferIndex = 0;
  HANDLE currentThreadId = NtGetCurrentThreadId();
  for (unsigned i = 0; i < currentProcessInfo->NumberOfThreads; ++i) {
    HANDLE threadId = currentProcessInfo->Threads[i].ClientId.UniqueThread;
    if (threadId != currentThreadId) {
      threadIdBuffer[threadIdBufferIndex++] = HandleToUlong(threadId);
    }
  }

  // set info
  threads->pItems = threadIdBuffer;
  threads->capacity = currentProcessInfo->NumberOfThreads;
  threads->size = threadIdBufferIndex;
  return NtFreeVirtualMemory(NtCurrentProcess(), processInfoBuffer, &bufferSize, MEM_RELEASE);
}

NTSYSCALLAPI
NTSTATUS
NTAPI
NtGetContextThread(
    _In_ HANDLE ThreadHandle,
    _Inout_ PCONTEXT ThreadContext
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetContextThread(
    _In_ HANDLE ThreadHandle,
    _In_ PCONTEXT ThreadContext
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSuspendThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtResumeThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
);

HANDLE
NativeOpenThread(IN DWORD dwDesiredAccess,
                 IN BOOL bInheritHandle,
                 IN DWORD dwThreadId) {
  NTSTATUS Status;
  HANDLE ThreadHandle;
  OBJECT_ATTRIBUTES ObjectAttributes;
  CLIENT_ID ClientId;

  ClientId.UniqueProcess = 0;
  ClientId.UniqueThread = ULongToHandle(dwThreadId);

  InitializeObjectAttributes(&ObjectAttributes,
                             NULL,
                             (bInheritHandle ? OBJ_INHERIT : 0),
                             NULL,
                             NULL);

  Status = NtOpenThread(&ThreadHandle,
                        dwDesiredAccess,
                        &ObjectAttributes,
                        &ClientId);
  if (!NT_SUCCESS(Status)) {
    return NULL;
  }

  return ThreadHandle;
}


#endif //MINHOOK_THREAD_NATIVE_H
