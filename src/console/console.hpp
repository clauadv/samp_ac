#pragma once

namespace console {
	inline bool m_initialize{ false };

	__forceinline void intialize() {
		if (console::m_initialize) {
			return;
		}

		const auto is_console_allocated = li_fn(AllocConsole).safe()();
		const auto is_console_attached = li_fn(AttachConsole).safe()(li_fn(GetCurrentProcessId).safe()());

		freopen_s(reinterpret_cast<FILE**>(stdin), "CONIN$", "r", stdin);
		freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);

		li_fn(SetConsoleTitleA).safe()(std::string{ sk("samp_ac") }.c_str());

		std::cout << std::string{ sk("* proof of concept *") } << std::endl;
		std::cout << std::string{ sk("  samp_ac - https://github.com/clauadv/samp_ac/") } << std::endl << std::endl;

		console::m_initialize = is_console_allocated && is_console_attached;
	}

	__forceinline void deinitialize() {
		if (!console::m_initialize) {
			return;
		}

		fclose(stdout);
		fclose(stdin);

		li_fn(FreeConsole).safe()();
		li_fn(PostMessageW).safe()(li_fn(GetConsoleWindow).safe()(), WM_CLOSE, 0, 0);
	}
}