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

#pragma once

#if !(defined _M_IX86) && !(defined _M_X64) && !(defined __i386__) && !(defined __x86_64__)
#error MinHook supports only x86 and x64 systems.
#endif

#include <windows.h>

 // MinHook Error Codes.
typedef enum mh_status
{
    // unknown error. should not be returned.
    mh_unknown = -1,

    // successful.
    mh_ok = 0,

    // minhook is already initialized.
    mh_error_already_initialized,

    // minhook is not initialized yet, or already uninitialized.
    mh_error_not_initialized,

    // the hook for the specified target function is already created.
    mh_error_already_created,

    // the hook for the specified target function is not created yet.
    mh_error_not_created,

    // the hook for the specified target function is already enabled.
    mh_error_enabled,

    // the hook for the specified target function is not enabled yet, or already
    // disabled.
    mh_error_disabled,

    // the specified pointer is invalid. it points the address of non-allocated
    // and/or non-executable region.
    mh_error_not_executable,

    // the specified target function cannot be hooked.
    mh_error_unsupported_function,

    // failed to allocate memory.
    mh_error_memory_alloc,

    // failed to change the memory protection.
    mh_error_memory_protect,

    // the specified module is not loaded.
    mh_error_module_not_found,

    // the specified function is not found.
    mh_error_function_not_found
}
mh_status;

// Can be passed as a parameter to MH_EnableHook, MH_DisableHook,
// MH_QueueEnableHook or MH_QueueDisableHook.
#define mh_all_hooks NULL

#ifdef __cplusplus
extern "C" {
#endif

    // initialize the minhook library. you must call this function exactly once
    // at the beginning of your program.
    mh_status WINAPI mh_initialize(void);

    // deinitialize the minhook library. you must call this function exactly
    // once at the end of your program.
    mh_status WINAPI mh_deinitialize(void);

    // creates a hook for the specified target function, in disabled state.
    // parameters:
    //   ptarget     [in]  a pointer to the target function, which will be
    //                     overridden by the detour function.
    //   pdetour     [in]  a pointer to the detour function, which will override
    //                     the target function.
    //   pporiginal  [out] a pointer to the trampoline function, which will be
    //                     used to call the original target function.
    //                     this parameter can be null.
    mh_status WINAPI mh_create_hook(LPVOID ptarget, LPVOID pdetour, LPVOID* pporiginal);

    // creates a hook for the specified api function, in disabled state.
    // parameters:
    //   pszmodule   [in]  a pointer to the loaded module name which contains the
    //                     target function.
    //   pszprocname [in]  a pointer to the target function name, which will be
    //                     overridden by the detour function.
    //   pdetour     [in]  a pointer to the detour function, which will override
    //                     the target function.
    //   pporiginal  [out] a pointer to the trampoline function, which will be
    //                     used to call the original target function.
    //                     this parameter can be null.
    mh_status WINAPI mh_create_hook_api(
        LPCWSTR pszmodule, LPCSTR pszprocname, LPVOID pdetour, LPVOID* pporiginal);

    // creates a hook for the specified api function, in disabled state.
    // parameters:
    //   pszmodule   [in]  a pointer to the loaded module name which contains the
    //                     target function.
    //   pszprocname [in]  a pointer to the target function name, which will be
    //                     overridden by the detour function.
    //   pdetour     [in]  a pointer to the detour function, which will override
    //                     the target function.
    //   pporiginal  [out] a pointer to the trampoline function, which will be
    //                     used to call the original target function.
    //                     this parameter can be null.
    //   pptarget    [out] a pointer to the target function, which will be used
    //                     with other functions.
    //                     this parameter can be null.
    mh_status WINAPI mh_create_hook_api_ex(
        LPCWSTR pszmodule, LPCSTR pszprocname, LPVOID pdetour, LPVOID* pporiginal, LPVOID* pptarget);

    // removes an already created hook.
    // parameters:
    //   ptarget [in] a pointer to the target function.
    mh_status WINAPI mh_remove_hook(LPVOID ptarget);

    // enables an already created hook.
    // parameters:
    //   ptarget [in] a pointer to the target function.
    //                if this parameter is mh_all_hooks, all created hooks are
    //                enabled in one go.
    mh_status WINAPI mh_enable_hook(LPVOID ptarget);

    // disables an already created hook.
    // parameters:
    //   ptarget [in] a pointer to the target function.
    //                if this parameter is mh_all_hooks, all created hooks are
    //                disabled in one go.
    mh_status WINAPI mh_disable_hook(LPVOID ptarget);

    // queues to enable an already created hook.
    // parameters:
    //   ptarget [in] a pointer to the target function.
    //                if this parameter is mh_all_hooks, all created hooks are
    //                queued to be enabled.
    mh_status WINAPI mh_queue_enable_hook(LPVOID ptarget);

    // queues to disable an already created hook.
    // parameters:
    //   ptarget [in] a pointer to the target function.
    //                if this parameter is mh_all_hooks, all created hooks are
    //                queued to be disabled.
    mh_status WINAPI mh_queue_disable_hook(LPVOID ptarget);

    // applies all queued changes in one go.
    mh_status WINAPI mh_apply_queued(void);

    // translates the mh_status to its name as a string.
    const char* WINAPI mh_status_to_string(mh_status status);

#ifdef __cplusplus
}
#endif
