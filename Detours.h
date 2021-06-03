#pragma once
#include <windows.h>

class Patch {
public:
	Patch();
	Patch(LPVOID pTarget, const byte* buf, size_t size, bool initialAttached = false);
	Patch(const Patch&) = delete;
	Patch(Patch&&) = delete;
	~Patch();
	static LPVOID GetApiPointer(const char* module, const char* api);
	static LPVOID FindSignature(LPVOID begin, size_t size, const char* sig, const char* mask);
	void Attach(bool force = false);
	void Detach(bool force = false);
	LPVOID GetTarget();
	bool IsValid();
	bool IsCorrupted();
	Patch& operator=(const Patch&) = delete;
	Patch& operator=(Patch&& right) noexcept;
protected:
	LPVOID m_target;
	byte* m_patch;
	byte* m_orig;
	size_t m_size;
	bool m_attached;
};

class Detour : public Patch {
public:
	Detour();
	Detour(LPVOID pTarget, size_t asmSize, LPVOID pHook, bool initialAttached = false);
	Detour(const Detour&) = delete;
	Detour(Detour&&) = delete;
	Detour& operator=(const Detour&) = delete;
	Detour& operator=(Detour&& right) noexcept;
};

class Trampoline : public Detour {
public:
	Trampoline();
	Trampoline(LPVOID pTarget, size_t asmSize, LPVOID pHook, LPVOID* pOrig = NULL);
	Trampoline(const Trampoline&) = delete;
	Trampoline(Trampoline&&) = delete;
	~Trampoline();
	LPVOID GetGateway();
	Trampoline& operator=(const Trampoline&) = delete;
	Trampoline& operator=(Trampoline&& right) noexcept;
protected:
	LPVOID m_gateway;
	size_t m_asmSize;
};