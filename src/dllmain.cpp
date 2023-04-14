// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.hpp"

void watcher_thread() {
	for (;;) {
		std::this_thread::sleep_for(std::chrono::seconds(1));

		guard::watch();
	}
}

void main_thread() {
	// initialize console
	console::intialize();

	// initialize hooks
	hooks::initialize();

	// initialize guard
	guard::initialize();
}

bool DllMain(const HMODULE module, const unsigned int call_reason, void* reserved [[maybe_unused]] ) {
	li_fn(DisableThreadLibraryCalls).safe()(module);

	if (call_reason != DLL_PROCESS_ATTACH) {
		return false;
	}

	std::thread{ main_thread }.detach();
	std::thread{ watcher_thread }.detach();

	return true;
}