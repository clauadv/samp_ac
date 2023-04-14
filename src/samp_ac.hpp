#pragma once

#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <thread>
#include <vector>
#include <algorithm>
#include <filesystem>

#include <third_party/lazy_importer/lazy_importer.hpp>
#include <third_party/sk_crypter/sk_crypter.hpp>
#include <third_party/min_hook/include/min_hook.hpp>

#include "console/console.hpp"
#include "section/section.hpp"
#include "guard/guard.hpp"
#include "hooks/hooks.hpp"