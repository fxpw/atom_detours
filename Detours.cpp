#include "Detours.h"
#include <new>
#include <cassert>

static void WriteProtectedMemory(LPVOID pTarget, const byte* buf, size_t size)
{
    static HANDLE hProcess = GetCurrentProcess();
    DWORD dwOldProtect;
    VirtualProtect(pTarget, size, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    memcpy(pTarget, buf, size);
    VirtualProtect(pTarget, size, dwOldProtect, &dwOldProtect);
    FlushInstructionCache(hProcess, pTarget, size);
}

Patch::Patch() : m_target(NULL), m_patch(NULL), m_orig(NULL), m_size(0), m_attached(false) {}

Patch::Patch(LPVOID pTarget, const byte* buf, size_t size, bool initialAttached)
    : m_target(pTarget), m_patch(new byte[size]), m_orig(new byte[size]), m_size(size), m_attached(false)
{
    memcpy(m_patch, buf, size);
    if (initialAttached)
        Attach();
}

Patch::~Patch()
{
    if (m_attached) Detach();
    if (m_patch) delete[] m_patch;
    if (m_orig) delete[] m_orig;
}

LPVOID Patch::GetApiPointer(const char* module, const char* api)
{
    HMODULE hModule = GetModuleHandleA(module);
    if (!hModule) return NULL;
    return (LPVOID)GetProcAddress(hModule, api);
}

inline bool MemCmp(const byte* data, const char* sig, const char* mask)
{
    for (; *mask; ++data, ++sig, ++mask) {
        if (*mask == 'x' && *data != *sig)
            return false;
    }
    return true;
}

LPVOID Patch::FindSignature(LPVOID begin, size_t size, const char* sig, const char* mask)
{
    size_t len = strlen(mask) - 1;
    for (DWORD i = 0; i < (size - len); i++) {
        if (MemCmp((const byte*)((uintptr_t)begin + i), sig, mask))
            return (LPVOID)((uintptr_t)begin + i);
    }
    return NULL;
}


void Patch::Attach(bool force)
{
    if (m_attached && !force) return;
    if (!IsValid()) return;
    if (!m_attached) memcpy(m_orig, m_target, m_size);
    WriteProtectedMemory(m_target, m_patch, m_size);
    m_attached = true;
}

void Patch::Detach(bool force)
{
    if (!m_attached && !force) return;
    if (!IsValid()) return;
    WriteProtectedMemory(m_target, m_patch, m_size);
    m_attached = false;
}

LPVOID Patch::GetTarget()
{
    return m_target;
}

bool Patch::IsValid()
{
    return m_target && !IsBadCodePtr((FARPROC)m_target);
}

bool Patch::IsCorrupted()
{
    return memcmp(m_target, m_attached ? m_patch : m_orig, m_size) != 0;
}

Patch& Patch::operator=(Patch&& right) noexcept
{
    if (this != &right) {
        Patch::~Patch();

        m_target = right.m_target;
        m_patch = right.m_patch;
        right.m_patch = NULL;
        m_orig = right.m_orig;
        right.m_orig = NULL;
        m_size = right.m_size;
        m_attached = right.m_attached;
        right.m_attached = false;
    }
    return *this;
}

Detour::Detour() {}

Detour::Detour(LPVOID pTarget, size_t asmSize, LPVOID pHook, bool initialAttached)
{
    byte* buf = new byte[asmSize];
    buf[0] = 0xE9;
    *(DWORD*)(&buf[1]) = (DWORD)((intptr_t)pHook - (intptr_t)pTarget - 5);
    if (asmSize > 5) memset(&buf[5], 0x90, asmSize - 5);
    new (this) Patch(pTarget, buf, asmSize, initialAttached);
}

Detour& Detour::operator=(Detour&& right) noexcept
{
    if (this != &right) {
        Detour::~Detour();
        Patch::operator=(std::move(right));
    }
    return *this;
}

Trampoline::Trampoline() : m_asmSize(0), m_gateway(NULL) {}

Trampoline::Trampoline(LPVOID pTarget, size_t asmSize, LPVOID pHook, LPVOID* pOrig) : Detour(pTarget, asmSize, pHook, true), m_asmSize(asmSize)
{
    byte* gateway = (byte*)VirtualAlloc(NULL, asmSize + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    assert(gateway && "Allocation fail");
    memcpy(gateway, m_orig, asmSize);
    gateway[asmSize] = 0xE9;
    *(intptr_t*)(&gateway[asmSize + 1]) = ((intptr_t)pTarget + asmSize) - ((intptr_t)gateway + asmSize + 5);
    *pOrig = m_gateway = gateway;
}

Trampoline::~Trampoline()
{
    if (m_gateway) VirtualFree(m_gateway, m_asmSize + 5, MEM_RELEASE);
}

LPVOID Trampoline::GetGateway()
{
    return m_gateway;
}

Trampoline& Trampoline::operator=(Trampoline&& right) noexcept
{
    if (this != &right) {
        Trampoline::~Trampoline();
        Detour::operator=(std::move(right));
        m_gateway = right.m_gateway;
        right.m_gateway = NULL;
        m_asmSize = right.m_asmSize;
    }
    return *this;
}