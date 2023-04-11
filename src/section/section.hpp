#pragma once

namespace section {
	class c_section {
	public:
		void* m_region{ nullptr };
		int m_size{ 0 };
		std::string m_name{ sk("bugged e mai tare") };
		std::vector<int> m_original{};

		c_section(void* region, const int size, const std::string& name) {
			this->m_region = region;
			this->m_size = size;
			this->m_name = name;

			for (int i = 0; i < this->m_size; i++) {
				this->m_original.push_back(*(static_cast<unsigned char*>(this->m_region) + i));
			}
		}
	};
}