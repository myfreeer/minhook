#include "../include/MinHook.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

typedef int (WINAPI *IntFunc)(int);
typedef int (WINAPI *MessageBoxWPtr)(HWND, LPCWSTR, LPCWSTR, UINT);

typedef struct _VIRTUAL_OBJECT {
    LPVOID *vtable;
    int base;
} VIRTUAL_OBJECT;

typedef int (WINAPI *VirtualMethodPtr)(VIRTUAL_OBJECT *, int);

static int g_failures;
static int g_target_calls;
static int g_detour_calls;
static int g_api_detour_calls;
static int g_virtual_detour_calls;
static int g_many_detour_calls;
static int (WINAPI *g_original_add_one)(int);
static int (WINAPI *g_original_message_box_w)(HWND, LPCWSTR, LPCWSTR, UINT);
static VirtualMethodPtr g_original_virtual_method;
static volatile int g_remove_offset = 30;
static volatile int g_pair_offset_a = 100;
static volatile int g_pair_offset_b = 200;
static volatile int g_many_offsets[] = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30, 31, 32, 33, 34, 35, 36, 37, 38, 39
};

static void CheckStatus(const char *label, MH_STATUS actual, MH_STATUS expected)
{
    if (actual != expected)
    {
        fprintf(stderr, "%s: expected status %d, got %d\n", label, expected, actual);
        g_failures++;
    }
}

static void CheckBool(const char *label, int condition)
{
    if (!condition)
    {
        fprintf(stderr, "%s: check failed\n", label);
        g_failures++;
    }
}

static int CallIntFunc(volatile IntFunc *slot, int value)
{
    IntFunc fn = *slot;
    return fn(value);
}

static int CallVirtualMethod(VIRTUAL_OBJECT *self, int delta)
{
    volatile VirtualMethodPtr fn = (VirtualMethodPtr)self->vtable[0];
    return fn(self, delta);
}

NOINLINE int WINAPI AddOne(int value)
{
    g_target_calls++;
    return value + 1;
}

NOINLINE int WINAPI AddOneDetour(int value)
{
    g_detour_calls++;
    return g_original_add_one(value) + 10;
}

NOINLINE int WINAPI RemoveTarget(int value)
{
    return value + g_remove_offset;
}

NOINLINE int WINAPI RemoveTargetDetour(int value)
{
    return value + 3000;
}

NOINLINE int WINAPI PairTargetA(int value)
{
    return value + g_pair_offset_a;
}

NOINLINE int WINAPI PairTargetB(int value)
{
    return value + g_pair_offset_b;
}

NOINLINE int WINAPI PairDetourA(int value)
{
    return value + 1000;
}

NOINLINE int WINAPI PairDetourB(int value)
{
    return value + 2000;
}

NOINLINE int WINAPI VirtualMethod(VIRTUAL_OBJECT *self, int delta)
{
    return self->base + delta;
}

NOINLINE int WINAPI VirtualMethodDetour(VIRTUAL_OBJECT *self, int delta)
{
    g_virtual_detour_calls++;
    return g_original_virtual_method(self, delta) + 50;
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

#define DEFINE_MANY_TARGET(N)            \
    NOINLINE int WINAPI ManyTarget##N(int value) \
    {                                    \
        return value + g_many_offsets[N]; \
    }

DEFINE_MANY_TARGET(0)
DEFINE_MANY_TARGET(1)
DEFINE_MANY_TARGET(2)
DEFINE_MANY_TARGET(3)
DEFINE_MANY_TARGET(4)
DEFINE_MANY_TARGET(5)
DEFINE_MANY_TARGET(6)
DEFINE_MANY_TARGET(7)
DEFINE_MANY_TARGET(8)
DEFINE_MANY_TARGET(9)
DEFINE_MANY_TARGET(10)
DEFINE_MANY_TARGET(11)
DEFINE_MANY_TARGET(12)
DEFINE_MANY_TARGET(13)
DEFINE_MANY_TARGET(14)
DEFINE_MANY_TARGET(15)
DEFINE_MANY_TARGET(16)
DEFINE_MANY_TARGET(17)
DEFINE_MANY_TARGET(18)
DEFINE_MANY_TARGET(19)
DEFINE_MANY_TARGET(20)
DEFINE_MANY_TARGET(21)
DEFINE_MANY_TARGET(22)
DEFINE_MANY_TARGET(23)
DEFINE_MANY_TARGET(24)
DEFINE_MANY_TARGET(25)
DEFINE_MANY_TARGET(26)
DEFINE_MANY_TARGET(27)
DEFINE_MANY_TARGET(28)
DEFINE_MANY_TARGET(29)
DEFINE_MANY_TARGET(30)
DEFINE_MANY_TARGET(31)
DEFINE_MANY_TARGET(32)
DEFINE_MANY_TARGET(33)
DEFINE_MANY_TARGET(34)
DEFINE_MANY_TARGET(35)
DEFINE_MANY_TARGET(36)
DEFINE_MANY_TARGET(37)
DEFINE_MANY_TARGET(38)
DEFINE_MANY_TARGET(39)

NOINLINE int WINAPI ManyDetour(int value)
{
    g_many_detour_calls++;
    return value + 10000;
}

static IntFunc g_many_targets[] = {
    ManyTarget0,  ManyTarget1,  ManyTarget2,  ManyTarget3,  ManyTarget4,
    ManyTarget5,  ManyTarget6,  ManyTarget7,  ManyTarget8,  ManyTarget9,
    ManyTarget10, ManyTarget11, ManyTarget12, ManyTarget13, ManyTarget14,
    ManyTarget15, ManyTarget16, ManyTarget17, ManyTarget18, ManyTarget19,
    ManyTarget20, ManyTarget21, ManyTarget22, ManyTarget23, ManyTarget24,
    ManyTarget25, ManyTarget26, ManyTarget27, ManyTarget28, ManyTarget29,
    ManyTarget30, ManyTarget31, ManyTarget32, ManyTarget33, ManyTarget34,
    ManyTarget35, ManyTarget36, ManyTarget37, ManyTarget38, ManyTarget39
};
static volatile IntFunc g_add_one_slot = AddOne;
static volatile IntFunc g_remove_target_slot = RemoveTarget;
static volatile IntFunc g_pair_target_a_slot = PairTargetA;
static volatile IntFunc g_pair_target_b_slot = PairTargetB;

static void RunPreInitializeTests(void)
{
    CheckStatus("disable before init", MH_DisableHook((LPVOID)AddOne), MH_ERROR_NOT_INITIALIZED);
    CheckStatus("disable all before init", MH_DisableHook(MH_ALL_HOOKS), MH_ERROR_NOT_INITIALIZED);
    CheckStatus("queue before init", MH_QueueEnableHook((LPVOID)AddOne), MH_ERROR_NOT_INITIALIZED);
    CheckStatus("apply before init", MH_ApplyQueued(), MH_ERROR_NOT_INITIALIZED);
}

static void RunInitializedStateTests(void)
{
    CheckStatus("first init", MH_Initialize(), MH_OK);
    CheckStatus("second init", MH_Initialize(), MH_ERROR_ALREADY_INITIALIZED);
    CheckStatus("missing hook", MH_RemoveHook((LPVOID)AddOne), MH_ERROR_NOT_CREATED);
    CheckStatus("enable all no hooks", MH_EnableHook(MH_ALL_HOOKS), MH_OK);
    CheckStatus("disable all no hooks", MH_DisableHook(MH_ALL_HOOKS), MH_OK);
    CheckStatus("queue enable all no hooks", MH_QueueEnableHook(MH_ALL_HOOKS), MH_OK);
    CheckStatus("queue disable all no hooks", MH_QueueDisableHook(MH_ALL_HOOKS), MH_OK);
    CheckStatus("apply no queued changes", MH_ApplyQueued(), MH_OK);
    CheckStatus("queue missing hook", MH_QueueEnableHook((LPVOID)AddOne), MH_ERROR_NOT_CREATED);
}

static void RunInvalidCreateTests(void)
{
    int stackValue = 0;

    CheckStatus("null target", MH_CreateHook(NULL, (LPVOID)AddOneDetour, NULL),
                MH_ERROR_NOT_EXECUTABLE);
    CheckStatus("null detour", MH_CreateHook((LPVOID)AddOne, NULL, NULL),
                MH_ERROR_NOT_EXECUTABLE);
    CheckStatus("data target", MH_CreateHook(&stackValue, (LPVOID)AddOneDetour, NULL),
                MH_ERROR_NOT_EXECUTABLE);
}

static void RunBasicHookTests(void)
{
    CheckBool("baseline", CallIntFunc(&g_add_one_slot, 1) == 2);
    CheckBool("target call count", g_target_calls == 1);

    CheckStatus("create hook", MH_CreateHook((LPVOID)AddOne, (LPVOID)AddOneDetour,
                                            (LPVOID *)&g_original_add_one), MH_OK);
    CheckBool("trampoline set", g_original_add_one != NULL);
    CheckStatus("duplicate hook", MH_CreateHook((LPVOID)AddOne, (LPVOID)AddOneDetour, NULL),
                MH_ERROR_ALREADY_CREATED);
    CheckStatus("disable inactive", MH_DisableHook((LPVOID)AddOne), MH_ERROR_DISABLED);
    CheckStatus("enable hook", MH_EnableHook((LPVOID)AddOne), MH_OK);
    CheckStatus("enable active", MH_EnableHook((LPVOID)AddOne), MH_ERROR_ENABLED);
    CheckBool("detoured result", CallIntFunc(&g_add_one_slot, 1) == 12);
    CheckBool("detour call count", g_detour_calls == 1);
    CheckStatus("disable hook", MH_DisableHook((LPVOID)AddOne), MH_OK);
    CheckStatus("disable inactive again", MH_DisableHook((LPVOID)AddOne), MH_ERROR_DISABLED);
    CheckBool("restored result", CallIntFunc(&g_add_one_slot, 1) == 2);
    CheckStatus("remove basic hook", MH_RemoveHook((LPVOID)AddOne), MH_OK);
    CheckStatus("remove missing basic hook", MH_RemoveHook((LPVOID)AddOne), MH_ERROR_NOT_CREATED);
    g_original_add_one = NULL;
}

static void RunQueuedHookTests(void)
{
    CheckStatus("create queued hook", MH_CreateHook((LPVOID)AddOne, (LPVOID)AddOneDetour,
                                                   (LPVOID *)&g_original_add_one), MH_OK);
    CheckStatus("apply with unchanged queue", MH_ApplyQueued(), MH_OK);
    CheckStatus("queue enable", MH_QueueEnableHook((LPVOID)AddOne), MH_OK);
    CheckBool("queued not active", CallIntFunc(&g_add_one_slot, 2) == 3);
    CheckStatus("apply enable", MH_ApplyQueued(), MH_OK);
    CheckBool("queued active", CallIntFunc(&g_add_one_slot, 2) == 13);
    CheckStatus("queue enable already active", MH_QueueEnableHook((LPVOID)AddOne), MH_OK);
    CheckStatus("apply already active queue", MH_ApplyQueued(), MH_OK);
    CheckStatus("queue disable", MH_QueueDisableHook((LPVOID)AddOne), MH_OK);
    CheckStatus("apply disable", MH_ApplyQueued(), MH_OK);
    CheckBool("queued disabled", CallIntFunc(&g_add_one_slot, 2) == 3);
    CheckStatus("remove queued hook", MH_RemoveHook((LPVOID)AddOne), MH_OK);
    g_original_add_one = NULL;
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

static void RunVirtualHookTests(void)
{
    LPVOID target = NULL;
    LPVOID nullVtable[1] = { NULL };
    LPVOID vtable[1] = { (LPVOID)VirtualMethod };
    VIRTUAL_OBJECT missingVtable = { NULL, 7 };
    VIRTUAL_OBJECT missingMethod = { nullVtable, 7 };
    VIRTUAL_OBJECT object = { vtable, 7 };

    CheckStatus("virtual null instance",
                MH_CreateHookVirtualEx(NULL, 0, (LPVOID)VirtualMethodDetour, NULL, NULL),
                MH_ERROR_NOT_EXECUTABLE);
    CheckStatus("virtual null vtable",
                MH_CreateHookVirtualEx(&missingVtable, 0, (LPVOID)VirtualMethodDetour, NULL, NULL),
                MH_ERROR_NOT_EXECUTABLE);
    CheckStatus("virtual null method",
                MH_CreateHookVirtualEx(&missingMethod, 0, (LPVOID)VirtualMethodDetour, NULL, NULL),
                MH_ERROR_NOT_EXECUTABLE);
    CheckBool("virtual baseline", CallVirtualMethod(&object, 3) == 10);
    CheckStatus("create virtual hook",
                MH_CreateHookVirtualEx(&object, 0, (LPVOID)VirtualMethodDetour,
                                       (LPVOID *)&g_original_virtual_method, &target),
                MH_OK);
    CheckBool("virtual target set", target == (LPVOID)VirtualMethod);
    CheckBool("virtual trampoline set", g_original_virtual_method != NULL);
    CheckStatus("enable virtual hook", MH_EnableHook(target), MH_OK);
    CheckBool("virtual detoured", CallVirtualMethod(&object, 3) == 60);
    CheckBool("virtual detour count", g_virtual_detour_calls == 1);
    CheckStatus("disable virtual hook", MH_DisableHook(target), MH_OK);
    CheckBool("virtual restored", CallVirtualMethod(&object, 3) == 10);
    CheckStatus("remove virtual hook", MH_RemoveHook(target), MH_OK);
    g_original_virtual_method = NULL;
}

static void RunAllHookTests(void)
{
    CheckStatus("create pair a", MH_CreateHook((LPVOID)PairTargetA, (LPVOID)PairDetourA, NULL),
                MH_OK);
    CheckStatus("create pair b", MH_CreateHook((LPVOID)PairTargetB, (LPVOID)PairDetourB, NULL),
                MH_OK);
    CheckStatus("enable all pair", MH_EnableHook(MH_ALL_HOOKS), MH_OK);
    CheckBool("pair a enabled", CallIntFunc(&g_pair_target_a_slot, 1) == 1001);
    CheckBool("pair b enabled", CallIntFunc(&g_pair_target_b_slot, 1) == 2001);
    CheckStatus("enable all pair already enabled", MH_EnableHook(MH_ALL_HOOKS), MH_OK);
    CheckStatus("disable all pair", MH_DisableHook(MH_ALL_HOOKS), MH_OK);
    CheckBool("pair a disabled", CallIntFunc(&g_pair_target_a_slot, 1) == 101);
    CheckBool("pair b disabled", CallIntFunc(&g_pair_target_b_slot, 1) == 201);
    CheckStatus("queue enable all pair", MH_QueueEnableHook(MH_ALL_HOOKS), MH_OK);
    CheckStatus("apply enable all pair", MH_ApplyQueued(), MH_OK);
    CheckBool("pair a queued enabled", CallIntFunc(&g_pair_target_a_slot, 2) == 1002);
    CheckBool("pair b queued enabled", CallIntFunc(&g_pair_target_b_slot, 2) == 2002);
    CheckStatus("queue disable all pair", MH_QueueDisableHook(MH_ALL_HOOKS), MH_OK);
    CheckStatus("apply disable all pair", MH_ApplyQueued(), MH_OK);
    CheckStatus("remove pair a", MH_RemoveHook((LPVOID)PairTargetA), MH_OK);
    CheckStatus("remove pair b", MH_RemoveHook((LPVOID)PairTargetB), MH_OK);
}

static void RunRemoveEnabledHookTests(void)
{
    CheckStatus("create remove-enabled hook",
                MH_CreateHook((LPVOID)RemoveTarget, (LPVOID)RemoveTargetDetour, NULL), MH_OK);
    CheckStatus("enable remove-enabled hook", MH_EnableHook((LPVOID)RemoveTarget), MH_OK);
    CheckBool("remove-enabled detoured", CallIntFunc(&g_remove_target_slot, 5) == 3005);
    CheckStatus("remove enabled hook", MH_RemoveHook((LPVOID)RemoveTarget), MH_OK);
    CheckBool("remove-enabled restored", CallIntFunc(&g_remove_target_slot, 5) == 35);
}

static void RunManyHookChurnTests(void)
{
    size_t i;
    const size_t hookCount = sizeof(g_many_targets) / sizeof(g_many_targets[0]);

    for (i = 0; i < hookCount; ++i)
    {
        CheckStatus("create many hook",
                    MH_CreateHook((LPVOID)g_many_targets[i], (LPVOID)ManyDetour, NULL), MH_OK);
    }

    CheckStatus("enable many hooks", MH_EnableHook(MH_ALL_HOOKS), MH_OK);
    CheckBool("many first enabled", g_many_targets[0](11) == 10011);
    CheckBool("many middle enabled", g_many_targets[17](11) == 10011);
    CheckBool("many last enabled", g_many_targets[hookCount - 1](11) == 10011);
    CheckBool("many detours called", g_many_detour_calls == 3);
    CheckStatus("disable many hooks", MH_DisableHook(MH_ALL_HOOKS), MH_OK);
    CheckBool("many first disabled", g_many_targets[0](11) == 11);
    CheckBool("many middle disabled", g_many_targets[17](11) == 28);
    CheckBool("many last disabled", g_many_targets[hookCount - 1](11) == 50);

    for (i = 0; i < hookCount; ++i)
    {
        CheckStatus("remove many hook", MH_RemoveHook((LPVOID)g_many_targets[i]), MH_OK);
    }
}

static void RunStatusStringTests(void)
{
    CheckBool("status ok string", strcmp(MH_StatusToString(MH_OK), "MH_OK") == 0);
    CheckBool("status unknown string", strcmp(MH_StatusToString((MH_STATUS)12345), "(unknown)") == 0);
}

static void RunCleanupTests(void)
{
    CheckStatus("uninit", MH_Uninitialize(), MH_OK);
    CheckStatus("uninit again", MH_Uninitialize(), MH_ERROR_NOT_INITIALIZED);
    CheckStatus("reinit after cleanup", MH_Initialize(), MH_OK);
    CheckStatus("reinit apply no queue", MH_ApplyQueued(), MH_OK);
    CheckStatus("final uninit", MH_Uninitialize(), MH_OK);
}

int main(void)
{
    RunPreInitializeTests();
    RunInitializedStateTests();
    RunInvalidCreateTests();
    RunBasicHookTests();
    RunQueuedHookTests();
    RunApiHookTests();
    RunVirtualHookTests();
    RunAllHookTests();
    RunRemoveEnabledHookTests();
    RunManyHookChurnTests();
    RunStatusStringTests();
    RunCleanupTests();

    return g_failures == 0 ? 0 : 1;
}
