#pragma once

namespace hooks::disable_thread_library_calls {
	using fn = int(__stdcall*)(HMODULE);
	inline fn m_original;
	int __stdcall hook(HMODULE h_lib_module);
}

namespace hooks::load_library_a {
	using fn = HMODULE(__stdcall*)(const char*);
	inline fn m_original;
	HMODULE __stdcall hook(const char* lp_lib_file_name);
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

		if (mh_create_hook_api(std::wstring{ sk(L"kernel32.dll") }.c_str(), std::string{ sk("LoadLibraryA") }.c_str(), &hooks::load_library_a::hook, reinterpret_cast<void**>(&hooks::load_library_a::m_original)) != mh_status::mh_ok) {
			std::cout << std::string{ sk("failed to create hook for load_library_a") } << std::endl;
		}

		if (mh_enable_hook(mh_all_hooks) != mh_status::mh_ok) {
			std::cout << std::string{ sk("failed to initialize hooks") } << std::endl;
			return;
		}

		std::cout << std::string{ sk("[samp_ac] hooks initialized") } << std::endl;
	}
}