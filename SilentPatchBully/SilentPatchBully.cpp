#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#define WINVER 0x0502
#define _WIN32_WINNT 0x0502

#include <windows.h>
#include <Xinput.h>

#include "Utils/MemoryMgr.h"
#include "PoolsBully.h"
#include "DefaultControllerConfig.h"

#include <cassert>

#include <Shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

#ifndef NDEBUG

#define INCLUDE_MEMORY_CHECKS 1
#define COMPILE_TEST_VERSION 0 // Timestamp instead of build ID in menu

#else

#define INCLUDE_MEMORY_CHECKS 0
#define COMPILE_TEST_VERSION 0 

#endif

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)


static HINSTANCE hDLLModule;
static HANDLE hShutdownEvent = NULL;

namespace FixedAllocators
{
	void InitMemoryMgr()
	{
		// Do nothing
	}

	void ShutDownMemoryMgr()
	{
		// Do nothing
	}

#if INCLUDE_MEMORY_CHECKS
	static constexpr size_t MEMORY_PROLOGUE_SIZE = sizeof(size_t) + sizeof(uint32_t);
	static constexpr size_t MEMORY_EPILOGUE_SIZE = sizeof(uint32_t);
	static constexpr size_t MEMORY_CANARIES_TOTAL_SIZE = MEMORY_PROLOGUE_SIZE + MEMORY_EPILOGUE_SIZE;

	static constexpr uint32_t MEMORY_CANARY = 0xDFDFDFDF;
#endif

	void* MemoryMgrMalloc(size_t size)
	{
		if (size == 0)
		{
			return nullptr;
		}

		// Their malloc is actually calloc, as allocated memory gets zeroed
#if INCLUDE_MEMORY_CHECKS
		// Debug memory is structured as follows:
		// Allocated size
		// FDFDFDFD
		// Allocated space
		// FDFDFDFD

		void* memory = calloc(size + MEMORY_CANARIES_TOTAL_SIZE, 1);
		assert(memory != nullptr);

		uintptr_t memStart = uintptr_t(memory);
		*(size_t*)memStart = size;
		*(uint32_t*)(memStart + sizeof(size_t)) = MEMORY_CANARY;
		*(uint32_t*)(memStart + MEMORY_PROLOGUE_SIZE + size) = MEMORY_CANARY;

		return (void*)(memStart + MEMORY_PROLOGUE_SIZE);
#else
		return calloc(size, 1);
#endif
	}

	void MemoryMgrFree(void* data)
	{
		if (data != nullptr)
		{
#if INCLUDE_MEMORY_CHECKS
			uintptr_t mem = uintptr_t(data);
			uint32_t startCanary = *(uint32_t*)(mem - sizeof(uint32_t));
			assert(startCanary == MEMORY_CANARY);
			*(uint32_t*)(mem - sizeof(uint32_t)) = ~MEMORY_CANARY;

			// If start canary is valid, we can check the end canary (since size is probably valid too)
			size_t size = *(size_t*)(mem - MEMORY_PROLOGUE_SIZE);
			uint32_t endCanary = *(uint32_t*)(mem + size);
			assert(endCanary == MEMORY_CANARY);
			*(uint32_t*)(mem + size) = ~MEMORY_CANARY;

			free((void*)(mem - MEMORY_PROLOGUE_SIZE));
#else
			free(data);
#endif
		}
	}

	void* RwMallocAlign(size_t size, size_t align)
	{
		if (size == 0)
		{
			return nullptr;
		}
		void* memory = _aligned_malloc(size, align);
		assert(memory != nullptr);
		return memory;
	}

	void RwFreeAlign(void* data)
	{
		if (data != nullptr)
		{
			_aligned_free(data);
		}
	}

	void __stdcall MemoryHeap_Free(void* data)
	{
		MemoryMgrFree(data);
	}

	void* __stdcall MemoryHeap_MoveMemoryBully(void* data)
	{
		// Do NOT move
		return data;
	}

	size_t __stdcall MemoryHeap_GetMemoryUsed(int)
	{
		return 0;
	}

};

namespace PedTypeShutdown
{
	static void (*orgOperatorDelete)(void* data);
	void OperatorDelete_Safe(void** pData)
	{
		if (*pData != nullptr)
		{
			orgOperatorDelete(*pData);
			*pData = nullptr;
		}
	}
}

namespace FrameTimingFix
{
	void (*orgUpdateTimer)(bool);
	void UpdateTimerAndSleep(bool captureInput)
	{
		orgUpdateTimer(captureInput);
		Sleep(100);
	}

}

#ifdef _DEBUG
#include <intrin.h>
#endif

namespace DoubleFreeOnExitFix
{
	class UnkInnerStruct
	{
	public:
		virtual void Unknown() = 0;
		virtual void Release() = 0;

		LONG refCount;

	public:
		void ReleaseTexture()
		{
			if (_InterlockedDecrement(&refCount) == 0)
			{
				Release();
			}
		}
	};

	class UnkStruct
	{
	public:
		uint8_t		__pad[52];
		UnkInnerStruct* m_pInner;
	};

	const auto FreeStruct = (void(*)(UnkStruct * ptr))0x752380;
	uint32_t ReleaseStruct(UnkStruct* ptr)
	{
		if (ptr == nullptr) return 1;
		auto* inner = ptr->m_pInner;
		if (inner == nullptr)
		{
			FreeStruct(ptr);
			return 1;
		}

		ptr->m_pInner = nullptr;
		inner->ReleaseTexture();

		return 1;
	}

	void ReleaseTextureAndNull(UnkInnerStruct** pPtr)
	{
		if (*pPtr != nullptr)
		{
			(*pPtr)->ReleaseTexture();
			*pPtr = nullptr;
		}
	}

	void RwTextureAddRef(UnkInnerStruct* ptr)
	{
		_InterlockedIncrement(&ptr->refCount);
	}

	uint32_t ReleaseTextureDebug(UnkInnerStruct* ptr)
	{
#ifndef _DEBUG
		ptr->ReleaseTexture();
#else
		assert(ptr->refCount > 0);
		void** mem = reinterpret_cast<void**>(ptr);
		if (_InterlockedDecrement(&ptr->refCount) == 0)
		{
			*mem = _ReturnAddress();
		}
#endif
		return 1;
	}

	static void (*orgPopTimer)();
	void PopTimer_AddMissingReferences()
	{
		UnkInnerStruct** texture = (UnkInnerStruct**)0xC66E40;
		for (size_t i = 0; i < 8; i++)
		{
			RwTextureAddRef(texture[i]);
		}

		orgPopTimer();
	}
};

// ============= Fix use-after-free when sndStream gets released before overlapped read finishes =============
class sndStream // Documented by P3ti
{
private:
	DWORD state;
	BYTE _pad_1_[16];
	DWORD mode;
	BYTE _pad_2_[44];
	float position[3];
	DWORD _80;
	int waveBankId;
	int soundBankId;
	int soundCueId;
	DWORD size;
	DWORD soundBankBuffer;
	HANDLE file;
	OVERLAPPED overlapped;
	DWORD playListId;
	DWORD fileReadStatus;
	DWORD playListEntry;
	DWORD offset;
	BYTE _pad_3_[272];

public:
	static inline void (sndStream::* orgCleanupStreamInfo)();
	void CleanupStreamInfo()
	{
		std::invoke(orgCleanupStreamInfo, this);
	}

	void CleanupStreamInfo_SilentPatch()
	{
		if (fileReadStatus == 2 || fileReadStatus == 3)
		{
			BOOL result = CancelIoEx(file, &overlapped);
			if (result != FALSE)
			{
				DWORD numberOfBytesTransferred;
				result = GetOverlappedResult(file, &overlapped, &numberOfBytesTransferred, TRUE);
				assert(result != FALSE);
			}
		}

		if (overlapped.hEvent != nullptr)
		{
			CloseHandle(overlapped.hEvent);
			overlapped.hEvent = nullptr;
		}

		CleanupStreamInfo();
	}
};

static_assert(sizeof(sndStream) == 0x1A0, "Wrong size: sndStream");

// ============= Fix handle leaks in ScreamSoundBank =============
class ScreamSoundBank // Documented by P3ti
{
private:
	BYTE _pad_1_[12];
	OVERLAPPED overlapped;
	BYTE _pad_2_[288];

public:
	static inline void (ScreamSoundBank::* orgKill)();
	void Kill()
	{
		std::invoke(orgKill, this);
	}

	void Kill_SilentPatch()
	{
		// Fix ScreamSoundBank overlapped I/O event handle leak
		if (overlapped.hEvent != nullptr)
		{
			CloseHandle(overlapped.hEvent);
			overlapped.hEvent = nullptr;
		}

		Kill();
	}
};

static_assert(sizeof(ScreamSoundBank) == 0x140, "Wrong size: ScreamSoundBank");

// ============= Fix memory leaks in Scream sound setups =============
namespace SEALeaksFix
{
	LPVOID RedirectMallocToCoTaskMemAlloc(SIZE_T size)
	{
		return CoTaskMemAlloc(size);
	}

	void RedirectFreeToCoTaskMemFree(LPVOID ptr)
	{
		CoTaskMemFree(ptr);
	}

	static inline DWORD(*MDXactCreateSoundBankCommand)(DWORD, DWORD, DWORD, DWORD);
	DWORD MDXactCreateSoundBankWithManagedDataCommand(DWORD buffer, DWORD size, DWORD /*flags*/, DWORD alloc_attributes)
	{
		return MDXactCreateSoundBankCommand(buffer, size, 1 /*XACT_FLAG_ENGINE_CREATE_MANAGEDATA*/, alloc_attributes);
	}

	// When failing use CoTaskMemFree if it's managed
	void MDXact_Manager_Internal_CreateInMemoryWaveBank(int id, LPVOID buffer, DWORD size, DWORD flags, DWORD alloc_attributes)
	{
		DWORD pXactEngine = *(DWORD*)0xCFACE0;
		if (pXactEngine == NULL)
		{
			return;
		}

		DWORD pfnCreateInMemoryWaveBank = *(DWORD*)(*(DWORD*)pXactEngine + 0x28);
		DWORD pXactWaveBank = NULL;
		if (SUCCEEDED((*(HRESULT(__stdcall*)(DWORD, LPVOID, DWORD, DWORD, DWORD, PDWORD))pfnCreateInMemoryWaveBank)(
			pXactEngine, buffer, size, flags, alloc_attributes, &pXactWaveBank)))
		{
			(*(void(__cdecl*)(DWORD))0x5AD810)(pXactWaveBank); // register ref counted wave bank
			(*(void(__cdecl*)(int))0x5AD4D0)(id);
			DWORD pMDXactWaveBank = (*(DWORD(__cdecl*)(DWORD))0x5EE830)(12); // MemoryMgrMalloc
			if (pMDXactWaveBank)
			{
				// MDXact_WaveBank ctor
				(*(DWORD(__thiscall*)(DWORD, DWORD, bool, int))0x5B0660)(pMDXactWaveBank, pXactWaveBank, false, id);
			}
			// NiTMap<int,MDXact_WaveBank *>::SetAt
			(*(DWORD(__thiscall*)(DWORD, int, DWORD))0x8A5140)(*(DWORD*)0xCFACE4, id, pMDXactWaveBank);
		}
		else
		{
			if (buffer != NULL)
			{
				if (flags & 0x00000001) // XACT_FLAG_ENGINE_CREATE_MANAGEDATA
					CoTaskMemFree(buffer);
				else
					(*(void(__cdecl*)(LPVOID))0x5EE940)(buffer); // MemoryMgrFree
			}

			(*(void(__cdecl*)(int))0x5AD5F0)(id); // remove shared data of wave bank
		}
	}

	// Do not ignore XACT flags, when failing use CoTaskMemFree if it's managed
	void MDXact_Manager_Internal_CreateSoundBank(int id, LPVOID buffer, DWORD size, DWORD flags, DWORD alloc_attributes)
	{
		DWORD pXactEngine = *(DWORD*)0xCFACE0;
		if (pXactEngine == NULL)
		{
			return;
		}

		DWORD pfnCreateSoundBank = *(DWORD*)(*(DWORD*)pXactEngine + 0x24);
		DWORD pXactSoundBank = NULL;
		if (SUCCEEDED((*(HRESULT(__stdcall*)(DWORD, LPVOID, DWORD, DWORD, DWORD, PDWORD))pfnCreateSoundBank)(
			pXactEngine, buffer, size, flags, alloc_attributes, &pXactSoundBank)))
		{
			(*(void(__cdecl*)(DWORD))0x5AD8E0)(pXactSoundBank); // register ref counted sound bank
			(*(void(__cdecl*)(int))0x5AD530)(id);
			DWORD pMDXactSoundBank = (*(DWORD(__cdecl*)(DWORD))0x5EE830)(24); // MemoryMgrMalloc
			if (pMDXactSoundBank)
			{
				// MDXact_SoundBank ctor
				(*(DWORD(__thiscall*)(DWORD, DWORD, int))0x5B04E0)(pMDXactSoundBank, pXactSoundBank, id);
			}
			// NiTMap<int,MDXact_SoundBank *>::SetAt
			(*(DWORD(__thiscall*)(DWORD, int, DWORD))0x8A5140)(*(DWORD*)0xCFACE8, id, pMDXactSoundBank);
		}
		else
		{
			if (buffer != NULL)
			{
				if (flags & 0x00000001) // XACT_FLAG_ENGINE_CREATE_MANAGEDATA
					CoTaskMemFree(buffer);
				else
					(*(void(__cdecl*)(LPVOID))0x5EE940)(buffer); // MemoryMgrFree
			}

			(*(void(__cdecl*)(int))0x5AD660)(id); // remove shared data of sound bank
		}
	}
};


DWORD WINAPI InputThread(LPVOID lpParam) {
	UNREFERENCED_PARAMETER(lpParam);
	int32_t* fps_cap = (int32_t*)0x406190;
	XINPUT_STATE xstate = { 0 };
	bool CordHeld = false;
	bool KeyHeld = false;
	while (WaitForSingleObject(hShutdownEvent, 100) == WAIT_TIMEOUT)
	{
		if (XInputGetState(0, &xstate) == ERROR_SUCCESS || !KeyHeld)
		{
			if (xstate.Gamepad.wButtons & XINPUT_GAMEPAD_BACK &&
				xstate.Gamepad.wButtons & XINPUT_GAMEPAD_DPAD_DOWN &&
				!CordHeld || ((GetAsyncKeyState(VK_F11) & 0x01) && !KeyHeld))
			{
				KeyHeld = true;
				wchar_t			wcModulePath[MAX_PATH];
				GetModuleFileNameW(hDLLModule, wcModulePath, _countof(wcModulePath) - 3); // Minus max required space for extension
				PathRenameExtensionW(wcModulePath, L".ini");

				if (const int INIoption = GetPrivateProfileIntW(L"SilentPatch", L"FPSLimit", -1, wcModulePath); INIoption != -1)
				{
					if (INIoption == 60)
					{
						if (WritePrivateProfileStringW(L"SilentPatch", L"FPSLimit", L"30", wcModulePath))
						{
							DWORD dwOldProtect;
							if (VirtualProtect(fps_cap, sizeof(int32_t), PAGE_EXECUTE_READWRITE, &dwOldProtect))
							{
								*(fps_cap) = 30;
								VirtualProtect(fps_cap, sizeof(int32_t), dwOldProtect, &dwOldProtect);
							}
						}
					}
					if (INIoption == 30)
					{
						if (WritePrivateProfileStringW(L"SilentPatch", L"FPSLimit", L"60", wcModulePath))
						{
							DWORD dwOldProtect;
							if (VirtualProtect(fps_cap, sizeof(int32_t), PAGE_EXECUTE_READWRITE, &dwOldProtect))
							{
								*(fps_cap) = 60;
								VirtualProtect(fps_cap, sizeof(int32_t), dwOldProtect, &dwOldProtect);
							}
						}
					}

				}
				if (xstate.Gamepad.wButtons & XINPUT_GAMEPAD_BACK &&
					xstate.Gamepad.wButtons & XINPUT_GAMEPAD_DPAD_DOWN)
				{
					CordHeld = true;
				}
			}
			if (!(xstate.Gamepad.wButtons & XINPUT_GAMEPAD_BACK) ||
				!(xstate.Gamepad.wButtons & XINPUT_GAMEPAD_DPAD_DOWN))
			{
				CordHeld = false;
			}

		}
		if (!GetAsyncKeyState(VK_F11) && KeyHeld)
		{
			KeyHeld = false;
		}
	}
	return 0; // Return value of the thread
}

LSTATUS RegSetKeyValueWLegacy(
	HKEY    hKey,
	LPCWSTR lpSubKey,
	LPCWSTR lpValueName,
	DWORD   dwType,
	LPCVOID lpData,
	DWORD   cbData
)
{
	LSTATUS Status;

	if (lpSubKey && *lpSubKey)
	{
		Status = RegCreateKeyExW(hKey, lpSubKey, 0, 0, 0, KEY_SET_VALUE, 0, &hKey, 0);

		if (Status != NOERROR)
		{
			return Status;
		}
	}

	Status = RegSetValueExW(hKey, lpValueName, 0, dwType,
		static_cast<PBYTE>(const_cast<void*>(lpData)), cbData);

	if (lpSubKey && *lpSubKey)
	{
		RegCloseKey(hKey);
	}

	return Status;
}


void InjectHooks()
{
	using namespace Memory;

	// If it's not 1.200, bail out
	if (!MemEquals(0x860C6B, { 0xC7, 0x45, 0xFC, 0xFE, 0xFF, 0xFF, 0xFF }))
	{
#ifndef _DEBUG
		MessageBoxW(nullptr, L"You are using an executable version not supported by SilentPatch (most likely 1.154)!\n\n"
			L"I strongly recommend obtaining a 1.200 executable - if you are using a retail version, just download an official 1.200 patch; "
			L"if you are using a Steam version, verify your game's files (since by default Steam uses 1.200).",
			L"SilentPatch", MB_OK | MB_ICONWARNING);
#endif
		return;
	}

	std::unique_ptr<ScopedUnprotect::Unprotect> Protect = ScopedUnprotect::UnprotectSectionOrFullModule(GetModuleHandle(nullptr), ".text");

	// Obtain a path to the ASI
	wchar_t			wcModulePath[MAX_PATH];
	LPCWSTR keyPath = L"Software\\Rockstar Games\\Bully Scholarship Edition\\A0"; // Path to the key
	GetModuleFileNameW(hDLLModule, wcModulePath, _countof(wcModulePath) - 3); // Minus max required space for extension
	PathRenameExtensionW(wcModulePath, L".ini");

	// Replaced custom CMemoryHeap with regular CRT functions (like in GTA)
	if (const int INIoption = GetPrivateProfileIntW(L"SilentPatch", L"CustomMemoryMgr", 0, wcModulePath); INIoption != 0)
	{
		using namespace FixedAllocators;

		InjectHook(0x5EE630, InitMemoryMgr, PATCH_JUMP);
		InjectHook(0x5EE5A0, ShutDownMemoryMgr, PATCH_JUMP);
		InjectHook(0x5EE830, MemoryMgrMalloc, PATCH_JUMP);
		InjectHook(0x5EE940, MemoryMgrFree, PATCH_JUMP);
		InjectHook(0x5EE9C0, RwMallocAlign, PATCH_JUMP);
		// 0x5EEA50 - RwMemoryMgrMalloc - jumps to MemoryMgrMalloc
		// 0x5EEA60 - RwMemoryMgrFree - jumps to MemoryMgrFree
		InjectHook(0x5EEA70, RwFreeAlign, PATCH_JUMP);

		InjectHook(0x5EEEF0, MemoryHeap_Free, PATCH_JUMP);
		InjectHook(0x5EF4D0, MemoryHeap_MoveMemoryBully, PATCH_JUMP);

		InjectHook(0x5EEDD0, MemoryHeap_GetMemoryUsed, PATCH_JUMP);

		// Write a pointer to fake 'upper memory bound' so CStreaming::MakeSpaceFor is pleased
		static const uintptr_t FAKE_MAX_MEMORY = 0x7FFFFFFF;
		Patch(0xD141A8, &FAKE_MAX_MEMORY);
	}

	// Fixed CPedType::Shutdown (zero pointers to prevent a double free)
	{
		using namespace PedTypeShutdown;

		Patch<uint8_t>(0x499CD8, 0x56);
		ReadCall(0x499CD9, orgOperatorDelete);
		InjectHook(0x499CD9, OperatorDelete_Safe);
	}

	// Don't call cSCREAMAudioManager::CleanupAfterMission from cSCREAMAudioManager::Terminate (used already freed memory)
	Nop(0x5963C3, 5);


	// Fixed a crash in CFileLoader::LoadCollisionModel occuring with a replaced allocator
	// Fixed COLL vertex loading
	Patch<uint8_t>(0x42BE80 + 2, 16);

	{
		using namespace FrameTimingFix;

		// DO NOT sleep when limiting FPS in game...
		Nop(0x4061C4, 2 + 6);

		// ...sleep for 100ms periodically when minimized
		ReadCall(0x43D660, orgUpdateTimer);
		InjectHook(0x43D660, UpdateTimerAndSleep);

		// Because we're doing a busy loop now, 31FPS cap can now become a 30FPS cap
		if (const int INIoption = GetPrivateProfileIntW(L"SilentPatch", L"FPSLimit", -1, wcModulePath); INIoption != -1)
		{
			Patch<int32_t>(0x40618F + 1, INIoption > 0 ? INIoption : INT_MAX);
		}

		if (const int INIoption = GetPrivateProfileIntW(L"SilentPatch", L"AntiAliasing", -1, wcModulePath); INIoption != -1)
		{
			LPCWSTR valueNameResH = L"AA";          // Name of the value
			RegSetKeyValueWLegacy(
				HKEY_CURRENT_USER, // Root key handle
				keyPath,           // Subkey path
				valueNameResH,         // Value name
				REG_DWORD,         // Value type
				&INIoption,        // Pointer to the data
				sizeof(INIoption)  // Size of the data in bytes
			);
		}

		if (const int INIoption = GetPrivateProfileIntW(L"SilentPatch", L"ResolutionHeight", -1, wcModulePath); INIoption != -1)
		{
			LPCWSTR valueNameResH = L"RESH";          // Name of the value
			RegSetKeyValueWLegacy(
				HKEY_CURRENT_USER, // Root key handle
				keyPath,           // Subkey path
				valueNameResH,         // Value name
				REG_DWORD,         // Value type
				&INIoption,        // Pointer to the data
				sizeof(INIoption)  // Size of the data in bytes
			);
		}

		if (const int INIoption = GetPrivateProfileIntW(L"SilentPatch", L"ResolutionWidth", -1, wcModulePath); INIoption != -1)
		{
			LPCWSTR valueNameResW = L"RESW";          // Name of the value
			RegSetKeyValueWLegacy(
				HKEY_CURRENT_USER, // Root key handle
				keyPath,           // Subkey path
				valueNameResW,         // Value name
				REG_DWORD,         // Value type
				&INIoption,        // Pointer to the data
				sizeof(INIoption)  // Size of the data in bytes
			);
		}

		if (const int INIoption = GetPrivateProfileIntW(L"SilentPatch", L"ShadowLevel", -1, wcModulePath); INIoption != -1)
		{
			LPCWSTR valueNameShadow = L"SHA";          // Name of the value
			RegSetKeyValueWLegacy(
				HKEY_CURRENT_USER, // Root key handle
				keyPath,           // Subkey path
				valueNameShadow,         // Value name
				REG_DWORD,         // Value type
				&INIoption,        // Pointer to the data
				sizeof(INIoption)  // Size of the data in bytes
			);
		}

		if (const int INIoption = GetPrivateProfileIntW(L"SilentPatch", L"Vsync", -1, wcModulePath); INIoption != -1)
		{
			LPCWSTR valueNameResH = L"VS";          // Name of the value
			RegSetKeyValueWLegacy(
				HKEY_CURRENT_USER, // Root key handle
				keyPath,           // Subkey path
				valueNameResH,         // Value name
				REG_DWORD,         // Value type
				&INIoption,        // Pointer to the data
				sizeof(INIoption)  // Size of the data in bytes
			);
		}

		if (const int INIoption = GetPrivateProfileIntW(L"SilentPatch", L"Windowed", -1, wcModulePath); INIoption != -1)
		{
			LPCWSTR valueNameResH = L"WIN";          // Name of the value
			RegSetKeyValueWLegacy(
				HKEY_CURRENT_USER, // Root key handle
				keyPath,           // Subkey path
				valueNameResH,         // Value name
				REG_DWORD,         // Value type
				&INIoption,        // Pointer to the data
				sizeof(INIoption)  // Size of the data in bytes
			);
		}

		if (const int INIoption = GetPrivateProfileIntW(L"SilentPatch", L"EnableControllers", -1, wcModulePath); INIoption != -1)
		{
			if (INIoption == 1 || INIoption == 0)
			{
				WCHAR configPath[MAX_PATH] = { 0 };
				if (ExpandEnvironmentStringsW(L"%USERPROFILE%\\Documents\\Bully Scholarship Edition\\ControllerSettings", configPath, MAX_PATH))
				{
					HANDLE hFile = CreateFileW(configPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
					if (hFile != INVALID_HANDLE_VALUE)
					{
						DWORD fs = GetFileSize(hFile, NULL);
						if (fs == 236)
						{
							UCHAR dataBuffer[236] = { 0 };
							if (ReadFile(hFile, dataBuffer, fs, 0, NULL))
							{
								CloseHandle(hFile);
								if (dataBuffer[0xA8] != (UCHAR)INIoption)
								{
									dataBuffer[0xA8] = (UCHAR)INIoption;
									HANDLE hFileNew = CreateFileW(configPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
									hFile = NULL;
									if (hFileNew != INVALID_HANDLE_VALUE)
									{
										WriteFile(hFileNew, dataBuffer, ARRAYSIZE(dataBuffer), 0, NULL);
										CloseHandle(hFileNew);
									}
								}
							}
						}
						else
						{
							CloseHandle(hFile);
							hFile = NULL;
							HANDLE hFileNew = CreateFileW(configPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
							if (hFileNew != INVALID_HANDLE_VALUE)
							{
								WriteFile(hFileNew, (INIoption == 0) ? DisabledControllerSettings : EnabledControllerSettings, ARRAYSIZE(EnabledControllerSettings), 0, NULL);
								CloseHandle(hFileNew);
							}
						}

					}
					else
					{
						HANDLE hFileNew = CreateFileW(configPath, FILE_WRITE_DATA, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
						if (hFileNew != INVALID_HANDLE_VALUE)
						{
							WriteFile(hFileNew, (INIoption == 0) ? DisabledControllerSettings : EnabledControllerSettings, ARRAYSIZE(EnabledControllerSettings), 0, NULL);
							CloseHandle(hFileNew);
						}
					}
				}
			}
		}
		// Revert code changes 60FPS EXE does, we don't need them anymore
		Patch<int8_t>(0x4061BE + 1, 0x4);
		Patch<uint8_t>(0x4061C2, 0x73);
	}

	// Remove FILE_FLAG_NO_BUFFERING from CdStreams
	Patch<uint32_t>(0x73ABEA + 6, FILE_FLAG_OVERLAPPED);


	// Fixed crash in Nutcracking
	// Consistently treat playercount as ID, not actual size
	Nop(0x6FB302, 6);
	Nop(0x6FB3EB, 6);
	Nop(0x6FC920, 2);
	Nop(0x6FC945, 2);
	Nop(0x6FC94F, 2);
	Nop(0x6FC97C, 2);
	Nop(0x6FCE91, 2);


	// Fixes for CBasePool misuse (object/projectile pools)
	{
		// Poor man's jitasm ;)
		auto pushEax = [](uintptr_t& addr)
			{
				Patch<uint8_t>(addr, 0x50);
				addr += 1;
			};

		auto pushEbx = [](uintptr_t& addr)
			{
				Patch<uint8_t>(addr, 0x53);
				addr += 1;
			};

		auto pushEsi = [](uintptr_t& addr)
			{
				Patch<uint8_t>(addr, 0x56);
				addr += 1;
			};

		auto pushEdi = [](uintptr_t& addr)
			{
				Patch<uint8_t>(addr, 0x57);
				addr += 1;
			};

		auto movEcxEbx = [](uintptr_t& addr)
			{
				Patch(addr, { 0x8B, 0xCB });
				addr += 2;
			};

		auto movEcxEbp = [](uintptr_t& addr)
			{
				Patch(addr, { 0x8B, 0xCD });
				addr += 2;
			};

		auto movEcxEsi = [](uintptr_t& addr)
			{
				Patch(addr, { 0x8B, 0xCE });
				addr += 2;
			};

		auto movEcxEdi = [](uintptr_t& addr)
			{
				Patch(addr, { 0x8B, 0xCF });
				addr += 2;
			};

		auto movEsiEax = [](uintptr_t& addr)
			{
				Patch(addr, { 0x8B, 0xF0 });
				addr += 2;
			};

		auto movEdiEax = [](uintptr_t& addr)
			{
				Patch(addr, { 0x8B, 0xF8 });
				addr += 2;
			};

		auto call = [](uintptr_t& addr, auto dest)
			{
				InjectHook(addr, dest, PATCH_CALL);
				addr += 5;
			};

		auto jmp = [](uintptr_t& addr, uintptr_t dest)
			{
				const ptrdiff_t offset = dest - (addr + 2);
				if (offset >= INT8_MIN && offset <= INT8_MAX)
				{
					Patch(addr, { 0xEB, static_cast<uint8_t>(offset) });
					addr += 2;
				}
				else
				{
					InjectHook(addr, dest, PATCH_JUMP);
					addr += 5;
				}
			};

		InjectHook(0x435BD0, &CBasePool::GetSlotWithLinked, PATCH_JUMP);
		InjectHook(0x436B90, &CBasePool::GetSlotWithLinkedWrapper, PATCH_JUMP);

		uintptr_t address;

		address = 0x4378D0;
		pushEdi(address);
		movEcxEbx(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x437901);

		address = 0x437A18;
		pushEdi(address);
		movEcxEbx(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x437A59);

		address = 0x437AA4;
		pushEsi(address);
		movEcxEdi(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		jmp(address, 0x437AD3);

		address = 0x44A4F6;
		pushEdi(address);
		movEcxEbx(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x44A527);

		address = 0x450A99;
		pushEsi(address);
		movEcxEbx(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		jmp(address, 0x450AC5);

		address = 0x45E72B;
		pushEsi(address);
		movEcxEdi(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		jmp(address, 0x45E757);

		address = 0x49E0D4;
		pushEdi(address);
		movEcxEbx(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x49E109);

		address = 0x49E489;
		pushEbx(address);
		movEcxEdi(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x49E4B8);

		address = 0x4CFE11;
		pushEdi(address);
		movEcxEbp(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x4CFE43);

		address = 0x4CFE91;
		pushEdi(address);
		movEcxEbp(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x4CFEC3);

		address = 0x4CFF24;
		pushEbx(address);
		movEcxEdi(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x4CFF59);

		address = 0x4D0138;
		pushEdi(address);
		movEcxEbx(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x4D0169);

		address = 0x4D01A0;
		pushEdi(address);
		movEcxEbx(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x4D01D1);

		address = 0x4D0211;
		pushEdi(address);
		movEcxEbp(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x4D0243);

		address = 0x4D02B0;
		pushEdi(address);
		movEcxEbp(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x4D02E2);

		address = 0x4D0350;
		pushEsi(address);
		movEcxEdi(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		jmp(address, 0x4D037F);

		address = 0x5309A6;
		pushEdi(address);
		movEcxEbp(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x5309D5);

		address = 0x532446;
		pushEsi(address);
		movEcxEdi(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		jmp(address, 0x532472);

		address = 0x5332DA;
		pushEbx(address);
		movEcxEdi(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x53330C);

		address = 0x5BCE62;
		pushEdi(address);
		movEcxEbx(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x5BCE97);

		address = 0x5C2642;
		pushEbx(address);
		movEcxEbp(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEdiEax(address);
		jmp(address, 0x5C2679);

		address = 0x5C2770;
		pushEbx(address);
		movEcxEbp(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEdiEax(address);
		jmp(address, 0x5C27A7);

		address = 0x5C2FC6;
		pushEdi(address);
		movEcxEsi(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		jmp(address, 0x5C2FF3);

		address = 0x5C31F0;
		pushEdi(address);
		movEcxEsi(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		jmp(address, 0x5C3220);

		address = 0x5C3280;
		pushEsi(address);
		movEcxEdi(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		jmp(address, 0x5C32AF);

		address = 0x5C33D6;
		pushEdi(address);
		movEcxEbx(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x5C3407);

		address = 0x5C4D91;
		pushEdi(address);
		movEcxEbp(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x5C4DC3);

		address = 0x677206;
		pushEdi(address);
		movEcxEbx(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		jmp(address, 0x67722E);

		address = 0x67C1AD;
		pushEdi(address);
		movEcxEbx(address);
		call(address, &CBasePool::GetSlotWithLinkedWrapper);
		movEsiEax(address);
		jmp(address, 0x67C1F2);
	}

	// Don't fail if call to CoInitializeEx didn't return S_TRUE (maybe something else called CoInitializeEx on us already)
	Nop(0x5AE2B4, 6);


	// Version number with SP build in main menu
#if COMPILE_TEST_VERSION
	Patch<const char*>(0x6A69EA + 1, "SP Test " __DATE__ " " __TIME__);
#else
	Patch<const char*>(0x6A69EA + 1, "%1.3f SP Build " STRINGIZE(SILENTPATCH_REVISION_ID));
#endif


	// Fix heap corruptions on exit
	{
		using namespace DoubleFreeOnExitFix;

		InjectHook(0x519090, ReleaseStruct, PATCH_JUMP);

		Patch<uint8_t>(0x55E0E2, 0x56); // push esi
		InjectHook(0x55E0E3, ReleaseTextureAndNull);

		// Series of identical calls to patch...
		auto fixEax = [](uintptr_t& addr, uintptr_t extra = 0)
			{
				Patch(addr, { 0xB8 });
				addr += 5 + 1 + extra;
				InjectHook(addr, DoubleFreeOnExitFix::ReleaseTextureAndNull);
				addr += 5;
			};

		auto fixEcx = [](uintptr_t& addr, uintptr_t extra = 0)
			{
				Patch(addr, { 0x90, 0xB9 });
				addr += 6 + 1 + extra;
				InjectHook(addr, DoubleFreeOnExitFix::ReleaseTextureAndNull);
				addr += 5;
			};

		auto fixEdx = [](uintptr_t& addr, uintptr_t extra = 0)
			{
				Patch(addr, { 0x90, 0xBA });
				addr += 6 + 1 + extra;
				InjectHook(addr, DoubleFreeOnExitFix::ReleaseTextureAndNull);
				addr += 5;
			};

		uintptr_t address = 0x528622;
		fixEdx(address);
		fixEax(address);
		fixEcx(address);

		fixEdx(address);
		fixEax(address);
		fixEcx(address);

		fixEdx(address);
		fixEax(address);
		fixEcx(address);

		fixEdx(address);
		fixEax(address);
		fixEcx(address);

		fixEdx(address);
		fixEax(address);
		fixEcx(address);

		// add esp in code...
		fixEdx(address);
		fixEax(address, 3);
		fixEcx(address);

		fixEdx(address);
		fixEax(address);
		fixEcx(address);

		fixEdx(address);
		fixEax(address);


		// Missing reference adding...
		ReadCall(0x514D98, orgPopTimer);
		InjectHook(0x514D98, PopTimer_AddMissingReferences);

		// TEMPORARY DEBUG
		//InjectHook( 0x5F0F90, ReleaseTextureDebug, PATCH_JUMP );
	}

	// Don't call RwFrameDestroy from CameraDestroy (crashes for some reason)
	Patch<uint8_t>(0x5EF954, 0xEB);


	// Fix use-after-free when sndStream gets released before overlapped read finishes
	{
		ReadCall(0x5A6EA9, sndStream::orgCleanupStreamInfo);
		InjectHook(0x5A6EA9, &sndStream::CleanupStreamInfo_SilentPatch);
		InjectHook(0x5A71D0, &sndStream::CleanupStreamInfo_SilentPatch);
		InjectHook(0x5A72D2, &sndStream::CleanupStreamInfo_SilentPatch);
		InjectHook(0x5A753F, &sndStream::CleanupStreamInfo_SilentPatch);
		InjectHook(0x5A79BF, &sndStream::CleanupStreamInfo_SilentPatch);
		InjectHook(0x5A7B21, &sndStream::CleanupStreamInfo_SilentPatch);
	}

	// Fix handle leaks in ScreamSoundBank
	{
		ReadCall(0x5A98D5, ScreamSoundBank::orgKill);
		InjectHook(0x5A98D5, &ScreamSoundBank::Kill_SilentPatch);
		InjectHook(0x5AA13F, &ScreamSoundBank::Kill_SilentPatch);
		InjectHook(0x5AA462, &ScreamSoundBank::Kill_SilentPatch);
	}


	// Fix memory leaks in Scream sound setups by allowing XACT to take ownership of allocations,
	// as it seemingly was intended to
	{
		using namespace SEALeaksFix;

		// Do not ignore XACT flags, when failing use CoTaskMemFree if it's managed
		InjectHook(0x5AE690, MDXact_Manager_Internal_CreateInMemoryWaveBank, PATCH_JUMP);
		InjectHook(0x5AE590, MDXact_Manager_Internal_CreateSoundBank, PATCH_JUMP);

		// In ScreamSoundBank::SetupSEA use CoTaskMemAlloc & CoTaskMemFree for XACT buffer
		InjectHook(0x5A990D, RedirectMallocToCoTaskMemAlloc);
		InjectHook(0x5A99FB, RedirectMallocToCoTaskMemAlloc);
		InjectHook(0x5A9B32, RedirectFreeToCoTaskMemFree);

		// Let XACT manage memory of SEA wave and sound banks
		Patch<int8_t>(0x5A99AF, 1);
		ReadCall(0x5A9A1F, MDXactCreateSoundBankCommand);
		InjectHook(0x5A9A1F, MDXactCreateSoundBankWithManagedDataCommand);
	}
	HANDLE hThread;      // Handle to the newly created thread
	DWORD dwThreadId;    // ID of the newly created thread

	// Create a new thread that will execute InputThread.
	hThread = CreateThread(
		nullptr,             // Default security attributes (can be NULL)
		0,                   // Default stack size (0 means use default size)
		InputThread,    // Pointer to the thread function
		NULL,//(LPVOID)(*(int32_t *)0x40618F + 1),             // Parameter to pass to the thread function (can be NULL)
		0,                   // Default creation flags (0 means run immediately)
		&dwThreadId          // Pointer to a DWORD to receive the thread ID
	);
	if (hThread)
	{
		CloseHandle(hThread);
	}
}

static void ProcHook()
{
	static bool		bPatched = false;
	if (!bPatched)
	{
		bPatched = true;

		InjectHooks();
	}
}

static uint8_t orgCode[5];
static decltype(SystemParametersInfoA)* pOrgSystemParametersInfoA;
BOOL WINAPI SystemParametersInfoA_Hook(UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni)
{
	ProcHook();
	return pOrgSystemParametersInfoA(uiAction, uiParam, pvParam, fWinIni);
}

BOOL WINAPI SystemParametersInfoA_OverwritingHook(UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni)
{
	Memory::VP::Patch(pOrgSystemParametersInfoA, { orgCode[0], orgCode[1], orgCode[2], orgCode[3], orgCode[4] });
	return SystemParametersInfoA_Hook(uiAction, uiParam, pvParam, fWinIni);
}

static bool PatchIAT()
{
	HINSTANCE					hInstance = GetModuleHandle(nullptr);
	PIMAGE_NT_HEADERS			ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hInstance + ((PIMAGE_DOS_HEADER)hInstance)->e_lfanew);

	// Find IAT	
	PIMAGE_IMPORT_DESCRIPTOR	pImports = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hInstance + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// Find user32.dll
	for (; pImports->Name != 0; pImports++)
	{
		if (!_stricmp((const char*)((DWORD_PTR)hInstance + pImports->Name), "USER32.DLL"))
		{
			if (pImports->OriginalFirstThunk != 0)
			{
				PIMAGE_IMPORT_BY_NAME* pFunctions = (PIMAGE_IMPORT_BY_NAME*)((DWORD_PTR)hInstance + pImports->OriginalFirstThunk);

				// user32.dll found, find SystemParametersInfoA
				for (ptrdiff_t j = 0; pFunctions[j] != nullptr; j++)
				{
					if (!strcmp((const char*)((DWORD_PTR)hInstance + pFunctions[j]->Name), "SystemParametersInfoA"))
					{
						// Overwrite the address with the address to a custom SystemParametersInfoA
						DWORD			dwProtect[2];
						DWORD_PTR* pAddress = &((DWORD_PTR*)((DWORD_PTR)hInstance + pImports->FirstThunk))[j];

						VirtualProtect(pAddress, sizeof(DWORD_PTR), PAGE_EXECUTE_READWRITE, &dwProtect[0]);
						pOrgSystemParametersInfoA = **(decltype(pOrgSystemParametersInfoA)*)pAddress;
						*pAddress = (DWORD_PTR)SystemParametersInfoA_Hook;
						VirtualProtect(pAddress, sizeof(DWORD_PTR), dwProtect[0], &dwProtect[1]);

						return true;
					}
				}
			}
		}
	}
	return false;
}

static bool PatchIAT_ByPointers()
{
	pOrgSystemParametersInfoA = SystemParametersInfoA;
	memcpy(orgCode, pOrgSystemParametersInfoA, sizeof(orgCode));
	Memory::VP::InjectHook(pOrgSystemParametersInfoA, SystemParametersInfoA_OverwritingHook, PATCH_JUMP);
	return true;
}

static void InstallHooks()
{
	bool getStartupInfoHooked = PatchIAT();
	if (!getStartupInfoHooked)
	{
		PatchIAT_ByPointers();
	}
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	UNREFERENCED_PARAMETER(hinstDLL);
	UNREFERENCED_PARAMETER(lpvReserved);

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		if (hShutdownEvent == NULL)
		{
			hShutdownEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		}
		hDLLModule = hinstDLL;
	}
	if (fdwReason == DLL_PROCESS_DETACH)
	{
		SetEvent(hShutdownEvent); // Signal the event
	}
	return TRUE;
}

extern "C" __declspec(dllexport)
uint32_t GetBuildNumber()
{
	return (SILENTPATCH_REVISION_ID << 8) | SILENTPATCH_BUILD_ID;
}

extern "C"
{
	static LONG InitCount = 0;
	__declspec(dllexport) void InitializeASI()
	{
		if (_InterlockedCompareExchange(&InitCount, 1, 0) != 0) return;
		InstallHooks();
	}
}