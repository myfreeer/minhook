#include "../include/MinHook.h"

#include <windows.h>

typedef int (WINAPI *MessageBoxWPtr)(HWND, LPCWSTR, LPCWSTR, UINT);

static int g_failures;
static int g_target_calls;
static int g_detour_calls;
static int g_api_detour_calls;
static int (WINAPI *g_original_add_one)(int);
static int (WINAPI *g_original_message_box_w)(HWND, LPCWSTR, LPCWSTR, UINT);

static void CheckStatus(const char *label, MH_STATUS actual, MH_STATUS expected)
{
    (void)label;
    if (actual != expected)
        g_failures++;
}

static void CheckBool(const char *label, int condition)
{
    (void)label;
    if (!condition)
        g_failures++;
}

__declspec(noinline) int WINAPI AddOne(int value)
{
    g_target_calls++;
    return value + 1;
}

__declspec(noinline) int WINAPI AddOneDetour(int value)
{
    g_detour_calls++;
    return g_original_add_one(value) + 10;
}

static int WINAPI MessageBoxWDetour(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    (void)hWnd;
    (void)lpText;
    (void)lpCaption;
    (void)uType;
    g_api_detour_calls++;
    return 1234;
}

static void RunStateTests(void)
{
    CheckStatus("disable before init", MH_DisableHook((LPVOID)AddOne), MH_ERROR_NOT_INITIALIZED);
    CheckStatus("first init", MH_Initialize(), MH_OK);
    CheckStatus("second init", MH_Initialize(), MH_ERROR_ALREADY_INITIALIZED);
    CheckStatus("missing hook", MH_RemoveHook((LPVOID)AddOne), MH_ERROR_NOT_CREATED);
}

static void RunBasicHookTests(void)
{
    CheckBool("baseline", AddOne(1) == 2);
    CheckBool("target call count", g_target_calls == 1);

    CheckStatus("create hook", MH_CreateHook((LPVOID)AddOne, (LPVOID)AddOneDetour,
                                            (LPVOID *)&g_original_add_one), MH_OK);
    CheckBool("trampoline set", g_original_add_one != NULL);
    CheckStatus("duplicate hook", MH_CreateHook((LPVOID)AddOne, (LPVOID)AddOneDetour, NULL),
                MH_ERROR_ALREADY_CREATED);
    CheckStatus("disable inactive", MH_DisableHook((LPVOID)AddOne), MH_ERROR_DISABLED);
    CheckStatus("enable hook", MH_EnableHook((LPVOID)AddOne), MH_OK);
    CheckStatus("enable active", MH_EnableHook((LPVOID)AddOne), MH_ERROR_ENABLED);
    CheckBool("detoured result", AddOne(1) == 12);
    CheckBool("detour call count", g_detour_calls == 1);
    CheckStatus("disable hook", MH_DisableHook((LPVOID)AddOne), MH_OK);
    CheckStatus("disable inactive again", MH_DisableHook((LPVOID)AddOne), MH_ERROR_DISABLED);
    CheckBool("restored result", AddOne(1) == 2);
}

static void RunQueuedHookTests(void)
{
    CheckStatus("queue enable", MH_QueueEnableHook((LPVOID)AddOne), MH_OK);
    CheckBool("queued not active", AddOne(2) == 3);
    CheckStatus("apply enable", MH_ApplyQueued(), MH_OK);
    CheckBool("queued active", AddOne(2) == 13);
    CheckStatus("queue disable", MH_QueueDisableHook((LPVOID)AddOne), MH_OK);
    CheckStatus("apply disable", MH_ApplyQueued(), MH_OK);
    CheckBool("queued disabled", AddOne(2) == 3);
}

static void RunApiHookTests(void)
{
    LPVOID target = NULL;
    CheckStatus("create api hook",
                MH_CreateHookApiEx(L"user32.dll", "MessageBoxW", (LPVOID)MessageBoxWDetour,
                                   (LPVOID *)&g_original_message_box_w, &target),
                MH_OK);
    CheckBool("api target set", target != NULL);
    CheckBool("api trampoline set", g_original_message_box_w != NULL);
    CheckStatus("enable api hook", MH_EnableHook(target), MH_OK);
    CheckBool("api detoured result", MessageBoxW(NULL, L"", L"", 0) == 1234);
    CheckBool("api detour call count", g_api_detour_calls == 1);
    CheckStatus("disable api hook", MH_DisableHook(target), MH_OK);
    CheckStatus("remove api hook", MH_RemoveHook(target), MH_OK);
    CheckStatus("missing api module", MH_CreateHookApi(L"missing-minhook-test.dll", "x",
                                                       (LPVOID)MessageBoxWDetour, NULL),
                MH_ERROR_MODULE_NOT_FOUND);
    CheckStatus("missing api function", MH_CreateHookApi(L"user32.dll", "MissingMinHookTest",
                                                         (LPVOID)MessageBoxWDetour, NULL),
                MH_ERROR_FUNCTION_NOT_FOUND);
}

static void RunCleanupTests(void)
{
    CheckStatus("remove basic hook", MH_RemoveHook((LPVOID)AddOne), MH_OK);
    CheckStatus("remove missing basic hook", MH_RemoveHook((LPVOID)AddOne), MH_ERROR_NOT_CREATED);
    CheckStatus("uninit", MH_Uninitialize(), MH_OK);
    CheckStatus("uninit again", MH_Uninitialize(), MH_ERROR_NOT_INITIALIZED);
}

int main(void)
{
    RunStateTests();
    RunBasicHookTests();
    RunQueuedHookTests();
    RunApiHookTests();
    RunCleanupTests();

    return g_failures == 0 ? 0 : 1;
}
