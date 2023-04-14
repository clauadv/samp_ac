#include "pch.hpp"

HMODULE __stdcall hooks::load_library_a::hook(const char* lp_lib_file_name) {
	std::string lib{ lp_lib_file_name };
	std::transform(lib.begin(), lib.end(), lib.begin(), ::tolower);

	// @note: we should use GetModuleFileName instead but filesystem is enough i guess
	auto current_path{ (std::filesystem::current_path() / std::string{ sk("quicktime.qts") }).string() };
	std::transform(current_path.begin(), current_path.end(), current_path.begin(), ::tolower);

	std::vector<std::string> allowed_libs = {
		std::string{ sk("c:\\windows\\system32\\quicktime.qts") },
		std::string{ sk("c:\\windows\\system32\\imm32.dll") },
		std::string{ sk("c:\\windows\\system32\\version.dll") },
		std::string{ sk("c:\\windows\\system32\\user32.dll") },
		std::string{ sk("user32.dll") },
		std::string{ sk("gdi32.dll") },
		std::string{ sk("setupapi.dll") },
		std::string{ sk("d3d8.dll") },
		std::string{ sk("dpnhpast.dll") },
		std::string{ sk("d3d9.dll") },
		std::string{ sk("ddraw.dll") },
		std::string{ sk("dsound.dll") },
		std::string{ sk("dinput8.dll") },
		std::string{ sk("d3dcompiler_43.dll") },
		std::string{ sk("wmvcore.dll") },
		std::string{ sk("imm32.dll") },
		std::string{ sk("version.dll") },
		std::string{ sk("quicktime.qts") },
		std::string{ sk("dsound") },
		current_path
	};

	if (std::find(allowed_libs.begin(), allowed_libs.end(), lib) == allowed_libs.end()) {
		std::cout << std::string{ sk("[samp_ac] load_library was called with the param ") } << lib << std::endl;

		std::terminate();
	}

	return hooks::load_library_a::m_original(lp_lib_file_name);
}