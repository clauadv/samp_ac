// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.hpp"

void watcher_thread() {
	for (;;) {
		std::this_thread::sleep_for(std::chrono::seconds(1));

		guard::watch();
	}
}

void main_thread() {
	console::intialize();

	const auto samp = li_fn(GetModuleHandleA).safe()(std::string{ sk("samp.dll") }.c_str());

	const auto fire_instant_hit = reinterpret_cast<unsigned long long>(samp) + 0xb05a0;
	const auto add_bullet = reinterpret_cast<unsigned long long>(samp) + 0xa0bb0;
	const auto rpc = reinterpret_cast<unsigned long long>(samp) + 0x30b30;
	const auto send_rpc = reinterpret_cast<unsigned long long>(samp) + 0x307f0;

	guard::add(reinterpret_cast<void*>(fire_instant_hit), 0xe3, std::string{ sk("fire_instant_hit")});
	guard::add(reinterpret_cast<void*>(add_bullet), 0x51, std::string{ sk("add_bullet") });
	guard::add(reinterpret_cast<void*>(rpc), 0xdc, std::string{ sk("rpc") });
	guard::add(reinterpret_cast<void*>(send_rpc), 0x89, std::string{ sk("send_rpc") });
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