#pragma once

namespace guard {
	inline std::vector<section::c_section> m_sections;

	__forceinline bool add(void* region, int size, const std::string& name) {
		guard::m_sections.emplace_back(reinterpret_cast<void*>(region), size, name);
		std::cout << std::string{ sk("[samp_ac] guarding ") } << name << std::string{ sk(" -> 0x") } << std::hex << reinterpret_cast<unsigned long long>(region) << std::endl;

		return true;
	}

	__forceinline std::vector<int> get(const std::vector<section::c_section>::value_type& value) {
		auto opcode = std::vector<int>{};
		for (auto i = 0; i < value.m_size; i++) {
			opcode.push_back(*(static_cast<unsigned char*>(value.m_region) + i));
		}

		return opcode;
	}

	__forceinline bool check_for_jmp(void* address) {
		// original
		// 55  push ebp

		// hooked
		// e9  jmp <hk> adica ce folosesc toti astia de vand s0beit

		if (static_cast<int>(*static_cast<unsigned char*>(address)) == 0xe9) {
			std::cout << std::string{ sk("[samp_ac] found jmp at 0x") } << address << std::endl;
			return true;
		}

		return false;
	}

	__forceinline void watch() {
		if (guard::m_sections.empty()) {
			return;
		}

		// fire_instant_hit
		guard::check_for_jmp(guard::m_sections.at(0).m_region);

		for (const auto& section : guard::m_sections) {
			for (auto i = 0; i < section.m_size; i++)
			{
				const auto current = guard::get(section).at(i);
				const auto original = section.m_original.at(i);

				if (current == original) {
					continue;
				}

				std::cout << std::string{ sk("[samp_ac] mismatch detected in ") } << section.m_name.c_str() << std::string{ sk(" (0x") } << std::hex << original << std::string{ sk(" -> 0x") } << std::hex << current << std::string{ sk(")") } << std::endl;

				// @note: this is optional, not recommended since this can be easily hooked or you can use syscalls
				li_fn(WriteProcessMemory).safe()(li_fn(GetCurrentProcess).safe()(), reinterpret_cast<void*>(static_cast<unsigned char*>(section.m_region) + i), &original, 1, nullptr);
			}
		}
	}
};