#include "pch.hpp"

int __stdcall hooks::disable_thread_library_calls::hook(HMODULE h_lib_module) {
	char lp_base_name[MAX_PATH]{ 0 };
	li_fn(K32GetModuleBaseNameA).safe()(li_fn(GetCurrentProcess).safe()(), h_lib_module, lp_base_name, MAX_PATH);

	std::vector<std::string> allowed_modules = {
		std::string{ sk("dinput8.dll") },
		std::string{ sk("d3dcompiler_47_32.dll") },
		std::string{ sk("d3d8.dll") },
		std::string{ sk("d3d9.dll") },
		std::string{ sk("dciman32.dll") },
		std::string{ sk("d3dcompiler_43.dll") },
		std::string{ sk("wmasf.dll") }
	};

	std::string module{ lp_base_name };
	std::transform(module.begin(), module.end(), module.begin(), ::tolower);

	if (std::find(allowed_modules.begin(), allowed_modules.end(), module) == allowed_modules.end()) {
		std::cout << std::string{ sk("[samp_ac] unknown module found -> ")} << h_lib_module << std::endl;

		// @todo: unload the module
		std::terminate();
	}

	return hooks::disable_thread_library_calls::m_original(h_lib_module);
}