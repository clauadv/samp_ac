/*
 *  MinHook - The Minimalistic API Hooking Library for x64/x86
 *  Copyright (C) 2009-2017 Tsuda Kageyu.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 *  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <limits.h>

#include "../include/min_hook.hpp"
#include "buffer.h"
#include "trampoline.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

 // Initial capacity of the HOOK_ENTRY buffer.
#define INITIAL_HOOK_CAPACITY   32

// Initial capacity of the thread IDs buffer.
#define INITIAL_THREAD_CAPACITY 128

// Special hook position values.
#define INVALID_HOOK_POS UINT_MAX
#define ALL_HOOKS_POS    UINT_MAX

// Freeze() action argument defines.
#define ACTION_DISABLE      0
#define ACTION_ENABLE       1
#define ACTION_APPLY_QUEUED 2

// Thread access rights for suspending/resuming threads.
#define THREAD_ACCESS \
    (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT)

// Hook information.
typedef struct _HOOK_ENTRY
{
    LPVOID pTarget;             // Address of the target function.
    LPVOID pDetour;             // Address of the detour or relay function.
    LPVOID pTrampoline;         // Address of the trampoline function.
    UINT8  backup[8];           // Original prologue of the target function.

    UINT8  patchAbove : 1;     // Uses the hot patch area.
    UINT8  isEnabled : 1;     // Enabled.
    UINT8  queueEnable : 1;     // Queued for enabling/disabling when != isEnabled.

    UINT   nIP : 4;             // Count of the instruction boundaries.
    UINT8  oldIPs[8];           // Instruction boundaries of the target function.
    UINT8  newIPs[8];           // Instruction boundaries of the trampoline function.
} HOOK_ENTRY, * PHOOK_ENTRY;

// Suspended threads for Freeze()/Unfreeze().
typedef struct _FROZEN_THREADS
{
    LPDWORD pItems;         // Data heap
    UINT    capacity;       // Size of allocated data heap, items
    UINT    size;           // Actual number of data items
} FROZEN_THREADS, * PFROZEN_THREADS;

//-------------------------------------------------------------------------
// Global Variables:
//-------------------------------------------------------------------------

// Spin lock flag for EnterSpinLock()/LeaveSpinLock().
volatile LONG g_isLocked = FALSE;

// Private heap handle. If not NULL, this library is initialized.
HANDLE g_hHeap = NULL;

// Hook entries.
struct
{
    PHOOK_ENTRY pItems;     // Data heap
    UINT        capacity;   // Size of allocated data heap, items
    UINT        size;       // Actual number of data items
} g_hooks;

//-------------------------------------------------------------------------
// Returns INVALID_HOOK_POS if not found.
static UINT FindHookEntry(LPVOID pTarget)
{
    UINT i;
    for (i = 0; i < g_hooks.size; ++i)
    {
        if ((ULONG_PTR)pTarget == (ULONG_PTR)g_hooks.pItems[i].pTarget)
            return i;
    }

    return INVALID_HOOK_POS;
}

//-------------------------------------------------------------------------
static PHOOK_ENTRY AddHookEntry()
{
    if (g_hooks.pItems == NULL)
    {
        g_hooks.capacity = INITIAL_HOOK_CAPACITY;
        g_hooks.pItems = (PHOOK_ENTRY)HeapAlloc(
            g_hHeap, 0, g_hooks.capacity * sizeof(HOOK_ENTRY));
        if (g_hooks.pItems == NULL)
            return NULL;
    } else if (g_hooks.size >= g_hooks.capacity)
    {
        PHOOK_ENTRY p = (PHOOK_ENTRY)HeapReAlloc(
            g_hHeap, 0, g_hooks.pItems, (g_hooks.capacity * 2) * sizeof(HOOK_ENTRY));
        if (p == NULL)
            return NULL;

        g_hooks.capacity *= 2;
        g_hooks.pItems = p;
    }

    return &g_hooks.pItems[g_hooks.size++];
}

//-------------------------------------------------------------------------
static VOID DeleteHookEntry(UINT pos)
{
    if (pos < g_hooks.size - 1)
        g_hooks.pItems[pos] = g_hooks.pItems[g_hooks.size - 1];

    g_hooks.size--;

    if (g_hooks.capacity / 2 >= INITIAL_HOOK_CAPACITY && g_hooks.capacity / 2 >= g_hooks.size)
    {
        PHOOK_ENTRY p = (PHOOK_ENTRY)HeapReAlloc(
            g_hHeap, 0, g_hooks.pItems, (g_hooks.capacity / 2) * sizeof(HOOK_ENTRY));
        if (p == NULL)
            return;

        g_hooks.capacity /= 2;
        g_hooks.pItems = p;
    }
}

//-------------------------------------------------------------------------
static DWORD_PTR FindOldIP(PHOOK_ENTRY pHook, DWORD_PTR ip)
{
    UINT i;

    if (pHook->patchAbove && ip == ((DWORD_PTR)pHook->pTarget - sizeof(JMP_REL)))
        return (DWORD_PTR)pHook->pTarget;

    for (i = 0; i < pHook->nIP; ++i)
    {
        if (ip == ((DWORD_PTR)pHook->pTrampoline + pHook->newIPs[i]))
            return (DWORD_PTR)pHook->pTarget + pHook->oldIPs[i];
    }

#if defined(_M_X64) || defined(__x86_64__)
    // Check relay function.
    if (ip == (DWORD_PTR)pHook->pDetour)
        return (DWORD_PTR)pHook->pTarget;
#endif

    return 0;
}

//-------------------------------------------------------------------------
static DWORD_PTR FindNewIP(PHOOK_ENTRY pHook, DWORD_PTR ip)
{
    UINT i;
    for (i = 0; i < pHook->nIP; ++i)
    {
        if (ip == ((DWORD_PTR)pHook->pTarget + pHook->oldIPs[i]))
            return (DWORD_PTR)pHook->pTrampoline + pHook->newIPs[i];
    }

    return 0;
}

//-------------------------------------------------------------------------
static VOID ProcessThreadIPs(HANDLE hThread, UINT pos, UINT action)
{
    // If the thread suspended in the overwritten area,
    // move IP to the proper address.

    CONTEXT c;
#if defined(_M_X64) || defined(__x86_64__)
    DWORD64* pIP = &c.Rip;
#else
    DWORD* pIP = &c.Eip;
#endif
    UINT count;

    c.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &c))
        return;

    if (pos == ALL_HOOKS_POS)
    {
        pos = 0;
        count = g_hooks.size;
    } else
    {
        count = pos + 1;
    }

    for (; pos < count; ++pos)
    {
        PHOOK_ENTRY pHook = &g_hooks.pItems[pos];
        BOOL        enable;
        DWORD_PTR   ip;

        switch (action)
        {
            case ACTION_DISABLE:
                enable = FALSE;
                break;

            case ACTION_ENABLE:
                enable = TRUE;
                break;

            default: // ACTION_APPLY_QUEUED
                enable = pHook->queueEnable;
                break;
        }
        if (pHook->isEnabled == enable)
            continue;

        if (enable)
            ip = FindNewIP(pHook, *pIP);
        else
            ip = FindOldIP(pHook, *pIP);

        if (ip != 0)
        {
            *pIP = ip;
            SetThreadContext(hThread, &c);
        }
    }
}

//-------------------------------------------------------------------------
static BOOL EnumerateThreads(PFROZEN_THREADS pThreads)
{
    BOOL succeeded = FALSE;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(hSnapshot, &te))
        {
            succeeded = TRUE;
            do
            {
                if (te.dwSize >= (FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD))
                    && te.th32OwnerProcessID == GetCurrentProcessId()
                    && te.th32ThreadID != GetCurrentThreadId())
                {
                    if (pThreads->pItems == NULL)
                    {
                        pThreads->capacity = INITIAL_THREAD_CAPACITY;
                        pThreads->pItems
                            = (LPDWORD)HeapAlloc(g_hHeap, 0, pThreads->capacity * sizeof(DWORD));
                        if (pThreads->pItems == NULL)
                        {
                            succeeded = FALSE;
                            break;
                        }
                    } else if (pThreads->size >= pThreads->capacity)
                    {
                        pThreads->capacity *= 2;
                        LPDWORD p = (LPDWORD)HeapReAlloc(
                            g_hHeap, 0, pThreads->pItems, pThreads->capacity * sizeof(DWORD));
                        if (p == NULL)
                        {
                            succeeded = FALSE;
                            break;
                        }

                        pThreads->pItems = p;
                    }
                    pThreads->pItems[pThreads->size++] = te.th32ThreadID;
                }

                te.dwSize = sizeof(THREADENTRY32);
            } while (Thread32Next(hSnapshot, &te));

            if (succeeded && GetLastError() != ERROR_NO_MORE_FILES)
                succeeded = FALSE;

            if (!succeeded && pThreads->pItems != NULL)
            {
                HeapFree(g_hHeap, 0, pThreads->pItems);
                pThreads->pItems = NULL;
            }
        }
        CloseHandle(hSnapshot);
    }

    return succeeded;
}

//-------------------------------------------------------------------------
static mh_status Freeze(PFROZEN_THREADS pThreads, UINT pos, UINT action)
{
    mh_status status = mh_ok;

    pThreads->pItems = NULL;
    pThreads->capacity = 0;
    pThreads->size = 0;
    if (!EnumerateThreads(pThreads))
    {
        status = mh_error_memory_alloc;
    } else if (pThreads->pItems != NULL)
    {
        UINT i;
        for (i = 0; i < pThreads->size; ++i)
        {
            HANDLE hThread = OpenThread(THREAD_ACCESS, FALSE, pThreads->pItems[i]);
            if (hThread != NULL)
            {
                SuspendThread(hThread);
                ProcessThreadIPs(hThread, pos, action);
                CloseHandle(hThread);
            }
        }
    }

    return status;
}

//-------------------------------------------------------------------------
static VOID Unfreeze(PFROZEN_THREADS pThreads)
{
    if (pThreads->pItems != NULL)
    {
        UINT i;
        for (i = 0; i < pThreads->size; ++i)
        {
            HANDLE hThread = OpenThread(THREAD_ACCESS, FALSE, pThreads->pItems[i]);
            if (hThread != NULL)
            {
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }

        HeapFree(g_hHeap, 0, pThreads->pItems);
    }
}

//-------------------------------------------------------------------------
static mh_status EnableHookLL(UINT pos, BOOL enable)
{
    PHOOK_ENTRY pHook = &g_hooks.pItems[pos];
    DWORD  oldProtect;
    SIZE_T patchSize = sizeof(JMP_REL);
    LPBYTE pPatchTarget = (LPBYTE)pHook->pTarget;

    if (pHook->patchAbove)
    {
        pPatchTarget -= sizeof(JMP_REL);
        patchSize += sizeof(JMP_REL_SHORT);
    }

    if (!VirtualProtect(pPatchTarget, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return mh_error_memory_protect;

    if (enable)
    {
        PJMP_REL pJmp = (PJMP_REL)pPatchTarget;
        pJmp->opcode = 0xE9;
        pJmp->operand = (UINT32)((LPBYTE)pHook->pDetour - (pPatchTarget + sizeof(JMP_REL)));

        if (pHook->patchAbove)
        {
            PJMP_REL_SHORT pShortJmp = (PJMP_REL_SHORT)pHook->pTarget;
            pShortJmp->opcode = 0xEB;
            pShortJmp->operand = (UINT8)(0 - (sizeof(JMP_REL_SHORT) + sizeof(JMP_REL)));
        }
    } else
    {
        if (pHook->patchAbove)
            memcpy(pPatchTarget, pHook->backup, sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
        else
            memcpy(pPatchTarget, pHook->backup, sizeof(JMP_REL));
    }

    VirtualProtect(pPatchTarget, patchSize, oldProtect, &oldProtect);

    // Just-in-case measure.
    FlushInstructionCache(GetCurrentProcess(), pPatchTarget, patchSize);

    pHook->isEnabled = enable;
    pHook->queueEnable = enable;

    return mh_ok;
}

//-------------------------------------------------------------------------
static mh_status EnableAllHooksLL(BOOL enable)
{
    mh_status status = mh_ok;
    UINT i, first = INVALID_HOOK_POS;

    for (i = 0; i < g_hooks.size; ++i)
    {
        if (g_hooks.pItems[i].isEnabled != enable)
        {
            first = i;
            break;
        }
    }

    if (first != INVALID_HOOK_POS)
    {
        FROZEN_THREADS threads;
        status = Freeze(&threads, ALL_HOOKS_POS, enable ? ACTION_ENABLE : ACTION_DISABLE);
        if (status == mh_ok)
        {
            for (i = first; i < g_hooks.size; ++i)
            {
                if (g_hooks.pItems[i].isEnabled != enable)
                {
                    status = EnableHookLL(i, enable);
                    if (status != mh_ok)
                        break;
                }
            }

            Unfreeze(&threads);
        }
    }

    return status;
}

//-------------------------------------------------------------------------
static VOID EnterSpinLock(VOID)
{
    SIZE_T spinCount = 0;

    // Wait until the flag is FALSE.
    while (InterlockedCompareExchange(&g_isLocked, TRUE, FALSE) != FALSE)
    {
        // No need to generate a memory barrier here, since InterlockedCompareExchange()
        // generates a full memory barrier itself.

        // Prevent the loop from being too busy.
        if (spinCount < 32)
            Sleep(0);
        else
            Sleep(1);

        spinCount++;
    }
}

//-------------------------------------------------------------------------
static VOID LeaveSpinLock(VOID)
{
    // No need to generate a memory barrier here, since InterlockedExchange()
    // generates a full memory barrier itself.

    InterlockedExchange(&g_isLocked, FALSE);
}

//-------------------------------------------------------------------------
mh_status WINAPI mh_initialize(VOID)
{
    mh_status status = mh_ok;

    EnterSpinLock();

    if (g_hHeap == NULL)
    {
        g_hHeap = HeapCreate(0, 0, 0);
        if (g_hHeap != NULL)
        {
            // Initialize the internal function buffer.
            InitializeBuffer();
        } else
        {
            status = mh_error_memory_alloc;
        }
    } else
    {
        status = mh_error_already_initialized;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
mh_status WINAPI mh_deinitialize(VOID)
{
    mh_status status = mh_ok;

    EnterSpinLock();

    if (g_hHeap != NULL)
    {
        status = EnableAllHooksLL(FALSE);
        if (status == mh_ok)
        {
            // Free the internal function buffer.

            // HeapFree is actually not required, but some tools detect a false
            // memory leak without HeapFree.

            UninitializeBuffer();

            HeapFree(g_hHeap, 0, g_hooks.pItems);
            HeapDestroy(g_hHeap);

            g_hHeap = NULL;

            g_hooks.pItems = NULL;
            g_hooks.capacity = 0;
            g_hooks.size = 0;
        }
    } else
    {
        status = mh_error_not_initialized;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
mh_status WINAPI mh_create_hook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal)
{
    mh_status status = mh_ok;

    EnterSpinLock();

    if (g_hHeap != NULL)
    {
        if (IsExecutableAddress(pTarget) && IsExecutableAddress(pDetour))
        {
            UINT pos = FindHookEntry(pTarget);
            if (pos == INVALID_HOOK_POS)
            {
                LPVOID pBuffer = AllocateBuffer(pTarget);
                if (pBuffer != NULL)
                {
                    TRAMPOLINE ct;

                    ct.pTarget = pTarget;
                    ct.pDetour = pDetour;
                    ct.pTrampoline = pBuffer;
                    if (CreateTrampolineFunction(&ct))
                    {
                        PHOOK_ENTRY pHook = AddHookEntry();
                        if (pHook != NULL)
                        {
                            pHook->pTarget = ct.pTarget;
                        #if defined(_M_X64) || defined(__x86_64__)
                            pHook->pDetour = ct.pRelay;
                        #else
                            pHook->pDetour = ct.pDetour;
                        #endif
                            pHook->pTrampoline = ct.pTrampoline;
                            pHook->patchAbove = ct.patchAbove;
                            pHook->isEnabled = FALSE;
                            pHook->queueEnable = FALSE;
                            pHook->nIP = ct.nIP;
                            memcpy(pHook->oldIPs, ct.oldIPs, ARRAYSIZE(ct.oldIPs));
                            memcpy(pHook->newIPs, ct.newIPs, ARRAYSIZE(ct.newIPs));

                            // Back up the target function.

                            if (ct.patchAbove)
                            {
                                memcpy(
                                    pHook->backup,
                                    (LPBYTE)pTarget - sizeof(JMP_REL),
                                    sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
                            } else
                            {
                                memcpy(pHook->backup, pTarget, sizeof(JMP_REL));
                            }

                            if (ppOriginal != NULL)
                                *ppOriginal = pHook->pTrampoline;
                        } else
                        {
                            status = mh_error_memory_alloc;
                        }
                    } else
                    {
                        status = mh_error_unsupported_function;
                    }

                    if (status != mh_ok)
                    {
                        FreeBuffer(pBuffer);
                    }
                } else
                {
                    status = mh_error_memory_alloc;
                }
            } else
            {
                status = mh_error_already_created;
            }
        } else
        {
            status = mh_error_not_executable;
        }
    } else
    {
        status = mh_error_not_initialized;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
mh_status WINAPI mh_remove_hook(LPVOID pTarget)
{
    mh_status status = mh_ok;

    EnterSpinLock();

    if (g_hHeap != NULL)
    {
        UINT pos = FindHookEntry(pTarget);
        if (pos != INVALID_HOOK_POS)
        {
            if (g_hooks.pItems[pos].isEnabled)
            {
                FROZEN_THREADS threads;
                status = Freeze(&threads, pos, ACTION_DISABLE);
                if (status == mh_ok)
                {
                    status = EnableHookLL(pos, FALSE);

                    Unfreeze(&threads);
                }
            }

            if (status == mh_ok)
            {
                FreeBuffer(g_hooks.pItems[pos].pTrampoline);
                DeleteHookEntry(pos);
            }
        } else
        {
            status = mh_error_not_created;
        }
    } else
    {
        status = mh_error_not_initialized;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
static mh_status EnableHook(LPVOID pTarget, BOOL enable)
{
    mh_status status = mh_ok;

    EnterSpinLock();

    if (g_hHeap != NULL)
    {
        if (pTarget == mh_all_hooks)
        {
            status = EnableAllHooksLL(enable);
        } else
        {
            UINT pos = FindHookEntry(pTarget);
            if (pos != INVALID_HOOK_POS)
            {
                if (g_hooks.pItems[pos].isEnabled != enable)
                {
                    FROZEN_THREADS threads;
                    status = Freeze(&threads, pos, ACTION_ENABLE);
                    if (status == mh_ok)
                    {
                        status = EnableHookLL(pos, enable);

                        Unfreeze(&threads);
                    }
                } else
                {
                    status = enable ? mh_error_enabled : mh_error_disabled;
                }
            } else
            {
                status = mh_error_not_created;
            }
        }
    } else
    {
        status = mh_error_not_initialized;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
mh_status WINAPI mh_enable_hook(LPVOID pTarget)
{
    return EnableHook(pTarget, TRUE);
}

//-------------------------------------------------------------------------
mh_status WINAPI mh_disable_hook(LPVOID pTarget)
{
    return EnableHook(pTarget, FALSE);
}

//-------------------------------------------------------------------------
static mh_status QueueHook(LPVOID pTarget, BOOL queueEnable)
{
    mh_status status = mh_ok;

    EnterSpinLock();

    if (g_hHeap != NULL)
    {
        if (pTarget == mh_all_hooks)
        {
            UINT i;
            for (i = 0; i < g_hooks.size; ++i)
                g_hooks.pItems[i].queueEnable = queueEnable;
        } else
        {
            UINT pos = FindHookEntry(pTarget);
            if (pos != INVALID_HOOK_POS)
            {
                g_hooks.pItems[pos].queueEnable = queueEnable;
            } else
            {
                status = mh_error_not_created;
            }
        }
    } else
    {
        status = mh_error_not_initialized;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
mh_status WINAPI mh_queue_enable_hook(LPVOID pTarget)
{
    return QueueHook(pTarget, TRUE);
}

//-------------------------------------------------------------------------
mh_status WINAPI mh_queue_disable_hook(LPVOID pTarget)
{
    return QueueHook(pTarget, FALSE);
}

//-------------------------------------------------------------------------
mh_status WINAPI mh_apply_queued(VOID)
{
    mh_status status = mh_ok;
    UINT i, first = INVALID_HOOK_POS;

    EnterSpinLock();

    if (g_hHeap != NULL)
    {
        for (i = 0; i < g_hooks.size; ++i)
        {
            if (g_hooks.pItems[i].isEnabled != g_hooks.pItems[i].queueEnable)
            {
                first = i;
                break;
            }
        }

        if (first != INVALID_HOOK_POS)
        {
            FROZEN_THREADS threads;
            status = Freeze(&threads, ALL_HOOKS_POS, ACTION_APPLY_QUEUED);
            if (status == mh_ok)
            {
                for (i = first; i < g_hooks.size; ++i)
                {
                    PHOOK_ENTRY pHook = &g_hooks.pItems[i];
                    if (pHook->isEnabled != pHook->queueEnable)
                    {
                        status = EnableHookLL(i, pHook->queueEnable);
                        if (status != mh_ok)
                            break;
                    }
                }

                Unfreeze(&threads);
            }
        }
    } else
    {
        status = mh_error_not_initialized;
    }

    LeaveSpinLock();

    return status;
}

//-------------------------------------------------------------------------
mh_status WINAPI mh_create_hook_api_ex(
    LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour,
    LPVOID* ppOriginal, LPVOID* ppTarget)
{
    HMODULE hModule;
    LPVOID  pTarget;

    hModule = GetModuleHandleW(pszModule);
    if (hModule == NULL)
        return mh_error_module_not_found;

    pTarget = (LPVOID)GetProcAddress(hModule, pszProcName);
    if (pTarget == NULL)
        return mh_error_function_not_found;

    if (ppTarget != NULL)
        *ppTarget = pTarget;

    return mh_create_hook(pTarget, pDetour, ppOriginal);
}

//-------------------------------------------------------------------------
mh_status WINAPI mh_create_hook_api(
    LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, LPVOID* ppOriginal)
{
    return mh_create_hook_api_ex(pszModule, pszProcName, pDetour, ppOriginal, NULL);
}

//-------------------------------------------------------------------------
const char* WINAPI MH_StatusToString(mh_status status)
{
#define MH_ST2STR(x)    \
    case x:             \
        return #x;

    switch (status) {
        MH_ST2STR(mh_unknown)
            MH_ST2STR(mh_ok)
            MH_ST2STR(mh_error_already_initialized)
            MH_ST2STR(mh_error_not_initialized)
            MH_ST2STR(mh_error_already_created)
            MH_ST2STR(mh_error_not_created)
            MH_ST2STR(mh_error_enabled)
            MH_ST2STR(mh_error_disabled)
            MH_ST2STR(mh_error_not_executable)
            MH_ST2STR(mh_error_unsupported_function)
            MH_ST2STR(mh_error_memory_alloc)
            MH_ST2STR(mh_error_memory_protect)
            MH_ST2STR(mh_error_module_not_found)
            MH_ST2STR(mh_error_function_not_found)
    }

#undef MH_ST2STR

    return "(unknown)";
}
