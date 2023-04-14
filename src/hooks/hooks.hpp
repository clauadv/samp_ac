#pragma once

namespace hooks::disable_thread_library_calls {
	using fn = int(__stdcall*)(HMODULE h_lib_module);
	inline fn m_original;
	int __stdcall hook(HMODULE h_lib_module);
}

namespace hooks {
	__forceinline void initialize() {
		if (mh_initialize() != mh_status::mh_ok) {
			std::cout << std::string{ sk("failed to initialize min_hook") } << std::endl;
			return;
		}

		if (mh_create_hook_api(std::wstring{ sk(L"kernel32.dll") }.c_str(), std::string{ sk("DisableThreadLibraryCalls") }.c_str(), &hooks::disable_thread_library_calls::hook, reinterpret_cast<void**>(&hooks::disable_thread_library_calls::m_original)) != mh_status::mh_ok) {
			std::cout << std::string{ sk("failed to create hook for disable_thread_library_calls") } << std::endl;
		}

		if (mh_enable_hook(mh_all_hooks) != mh_status::mh_ok) {
			std::cout << std::string{ sk("failed to initialize hooks") } << std::endl;
			return;
		}

		std::cout << std::string{ sk("[samp_ac] hooks initialized") } << std::endl;
	}
}