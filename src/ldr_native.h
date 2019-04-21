#ifndef MINHOOK_LDR_NATIVE_H
#define MINHOOK_LDR_NATIVE_H

#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif

#include <winternl.h>

NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllHandle(
    _In_opt_ PWSTR DllPath,
    _In_opt_ PULONG DllCharacteristics,
    _In_ PUNICODE_STRING DllName,
    _Out_ PVOID *DllHandle
);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetProcedureAddress(
    _In_  PVOID BaseAddress,
    _In_  PANSI_STRING Name,
    _In_  ULONG Ordinal,
    _Out_  PVOID *ProcedureAddress
);

static inline HMODULE LdrGetModuleHandleW(
    _In_opt_ LPCWSTR lpModuleName
)
{
  UNICODE_STRING usModuleName;
  HANDLE hModule;
  NTSTATUS status;

  RtlInitUnicodeString(&usModuleName, lpModuleName);
  status = LdrGetDllHandle(NULL, NULL, &usModuleName, &hModule);

  if (NT_SUCCESS(status)) {
    return (HMODULE)hModule;
  }

  return NULL;
}

static inline FARPROC LdrGetProcAddress(
    _In_ HMODULE hModule,
    _In_ LPCSTR  lpProcName
)
{
  ANSI_STRING procNameAnsi;
  RtlInitAnsiString(&procNameAnsi, lpProcName);

  FARPROC procAddress = NULL;
  NTSTATUS status = LdrGetProcedureAddress(hModule, &procNameAnsi, 0, (PVOID *)(&procAddress));
  return (NT_SUCCESS(status)) ? (procAddress) : (NULL);
}
#endif //MINHOOK_LDR_NATIVE_H
