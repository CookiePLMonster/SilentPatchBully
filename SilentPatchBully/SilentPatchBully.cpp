#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#define WINVER 0x0502
#define _WIN32_WINNT 0x0502

#include <windows.h>
#include "Utils/MemoryMgr.h"
#include "PoolsBully.h"

#include <cassert>

#include <Shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

#ifndef NDEBUG

#define INCLUDE_MEMORY_CHECKS 1

#else

#define INCLUDE_MEMORY_CHECKS 0

#endif

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)


static HINSTANCE hDLLModule;

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

	void* MemoryMgrMalloc( size_t size )
	{
		if ( size == 0 )
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

		void* memory = calloc( size + MEMORY_CANARIES_TOTAL_SIZE, 1 );
		assert( memory != nullptr );

		uintptr_t memStart = uintptr_t(memory);
		*(size_t*)memStart = size;
		*(uint32_t*)( memStart + sizeof(size_t) ) = MEMORY_CANARY;
		*(uint32_t*)( memStart + MEMORY_PROLOGUE_SIZE + size ) = MEMORY_CANARY;

		return (void*)( memStart + MEMORY_PROLOGUE_SIZE );
#else
		return calloc( size, 1 );
#endif
	}

	void MemoryMgrFree( void* data )
	{
		if ( data != nullptr )
		{
#if INCLUDE_MEMORY_CHECKS
			uintptr_t mem = uintptr_t(data);
			uint32_t startCanary = *(uint32_t*)(mem - sizeof(uint32_t));
			assert( startCanary == MEMORY_CANARY );
			*(uint32_t*)(mem - sizeof(uint32_t)) = ~MEMORY_CANARY;

			// If start canary is valid, we can check the end canary (since size is probably valid too)
			size_t size = *(size_t*)(mem - MEMORY_PROLOGUE_SIZE);
			uint32_t endCanary = *(uint32_t*)(mem + size);
			assert( endCanary == MEMORY_CANARY );
			*(uint32_t*)(mem + size) = ~MEMORY_CANARY;

			free( (void*)(mem - MEMORY_PROLOGUE_SIZE) );
#else
			free( data );
#endif
		}
	}

	void* RwMallocAlign( size_t size, size_t align )
	{
		if ( size == 0 )
		{
			return nullptr;
		}
		void* memory = _aligned_malloc( size, align );
		assert( memory != nullptr );
		return memory;
	}

	void RwFreeAlign( void* data )
	{
		if ( data != nullptr )
		{
			_aligned_free( data );
		}
	}

	void OperatorDelete_Safe( void** pData )
	{
		if ( *pData != nullptr )
		{
			MemoryMgrFree( *pData );
			*pData = nullptr;
		}
	}

	void __stdcall MemoryHeap_Free( void* data )
	{
		MemoryMgrFree( data );
	}

	void* __stdcall MemoryHeap_MoveMemoryBully( void* data )
	{
		// Do NOT move
		return data;
	}

	size_t __stdcall MemoryHeap_GetMemoryUsed( int )
	{
		return 0;
	}

};



namespace FrameTimingFix
{
	void (*orgUpdateTimer)(bool);
	void UpdateTimerAndSleep( bool captureInput )
	{
		orgUpdateTimer( captureInput );
		Sleep( 100 );
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
			if ( _InterlockedDecrement( &refCount ) == 0 )
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

	const auto FreeStruct = (void(*)(UnkStruct* ptr))0x752380;
	uint32_t ReleaseStruct( UnkStruct* ptr )
	{
		if ( ptr == nullptr ) return 1;
		auto* inner = ptr->m_pInner;
		if ( inner == nullptr )
		{
			FreeStruct( ptr );
			return 1;
		}

		ptr->m_pInner = nullptr;
		inner->ReleaseTexture();

		return 1;
	}

	void ReleaseTextureAndNull( UnkInnerStruct** pPtr )
	{
		if ( *pPtr != nullptr )
		{
			(*pPtr)->ReleaseTexture();
			*pPtr = nullptr;
		}
	}

	void RwTextureAddRef( UnkInnerStruct* ptr )
	{
		_InterlockedIncrement( &ptr->refCount );
	}

	uint32_t ReleaseTextureDebug( UnkInnerStruct* ptr )
	{
#ifndef _DEBUG
		ptr->ReleaseTexture();
#else
		assert( ptr->refCount > 0 );
		void** mem = reinterpret_cast<void**>(ptr);
		if ( _InterlockedDecrement( &ptr->refCount ) == 0 )
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
		for ( size_t i = 0; i < 8; i++ )
		{
			RwTextureAddRef( texture[i] );
		}

		orgPopTimer();
	}
};

void InjectHooks()
{
	using namespace Memory;

	// If it's not 1.200, bail out
	if ( !MemEquals( 0x860C6B, { 0xC7, 0x45, 0xFC, 0xFE, 0xFF, 0xFF, 0xFF } ) )
	{
#ifndef _DEBUG
		MessageBoxW( nullptr, L"You are using an executable version not supported by SilentPatch (most likely 1.154)!\n\n"
			L"I strongly recommend obtaining a 1.200 executable - if you are using a retail version, just download an official 1.200 patch; "
			L"if you are using a Steam version, verify your game's files (since by default Steam uses 1.200).",
			L"SilentPatch", MB_OK | MB_ICONWARNING );
#endif
		return;
	}

	std::unique_ptr<ScopedUnprotect::Unprotect> Protect = ScopedUnprotect::UnprotectSectionOrFullModule( GetModuleHandle( nullptr ), ".text" );

	// Obtain a path to the ASI
	wchar_t			wcModulePath[MAX_PATH];
	GetModuleFileNameW(hDLLModule, wcModulePath, _countof(wcModulePath) - 3); // Minus max required space for extension
	PathRenameExtensionW(wcModulePath, L".ini");

	// Replaced custom CMemoryHeap with regular CRT functions (like in GTA)
	{
		using namespace FixedAllocators;

		InjectHook( 0x5EE630, InitMemoryMgr, PATCH_JUMP );
		InjectHook( 0x5EE5A0, ShutDownMemoryMgr, PATCH_JUMP );		
		InjectHook( 0x5EE830, MemoryMgrMalloc, PATCH_JUMP );
		InjectHook( 0x5EE940, MemoryMgrFree, PATCH_JUMP );
		InjectHook( 0x5EE9C0, RwMallocAlign, PATCH_JUMP );
		// 0x5EEA50 - RwMemoryMgrMalloc - jumps to MemoryMgrMalloc
		// 0x5EEA60 - RwMemoryMgrFree - jumps to MemoryMgrFree
		InjectHook( 0x5EEA70, RwFreeAlign, PATCH_JUMP );

		InjectHook( 0x5EEEF0, MemoryHeap_Free, PATCH_JUMP );
		InjectHook( 0x5EF4D0, MemoryHeap_MoveMemoryBully, PATCH_JUMP );

		InjectHook( 0x5EEDD0, MemoryHeap_GetMemoryUsed, PATCH_JUMP );

		// Fixed CPedType::Shutdown (zero pointers to prevent a double free)
		Patch<uint8_t>( 0x499CD8, 0x56 );
		InjectHook( 0x499CD9, OperatorDelete_Safe );

		// Don't call cSCREAMAudioManager::CleanupAfterMission from cSCREAMAudioManager::Terminate (used already freed memory)
		Nop( 0x5963C3, 5 );

		// Write a pointer to fake 'upper memory bound' so CStreaming::MakeSpaceFor is pleased
		static const uintptr_t FAKE_MAX_MEMORY = 0x7FFFFFFF;
		Patch( 0xD141A8, &FAKE_MAX_MEMORY );
	}


	// Fixed a crash in CFileLoader::LoadCollisionModel occuring with a replaced allocator
	// Fixed COLL vertex loading
	Patch<uint8_t>( 0x42BE80 + 2, 16 );

	{
		using namespace FrameTimingFix;

		// DO NOT sleep when limiting FPS in game...
		Nop( 0x4061C4, 2 + 6 );

		// ...sleep for 100ms periodically when minimized
		ReadCall( 0x43D660, orgUpdateTimer );
		InjectHook( 0x43D660, UpdateTimerAndSleep );

		// Because we're doing a busy loop now, 31FPS cap can now become a 30FPS cap
		if ( const int INIoption = GetPrivateProfileIntW(L"SilentPatch", L"FPSLimit", -1, wcModulePath); INIoption != -1 )
		{
			Patch<int32_t>( 0x40618F + 1, INIoption > 0 ? INIoption : INT_MAX );
		}

		// Revert code changes 60FPS EXE does, we don't need them anymore
		Patch<int8_t>( 0x4061BE + 1, 0x4 );
		Patch<uint8_t>( 0x4061C2, 0x73 );
	}

	// Remove FILE_FLAG_NO_BUFFERING from CdStreams
	Patch<uint32_t>( 0x73ABEA + 6, FILE_FLAG_OVERLAPPED );


	// Fixed crash in Nutcracking
	// Consistently treat playercount as ID, not actual size
	Nop( 0x6FB302, 6 );
	Nop( 0x6FB3EB, 6 );
	Nop( 0x6FC920, 2 );
	Nop( 0x6FC945, 2 );
	Nop( 0x6FC94F, 2 );
	Nop( 0x6FC97C, 2 );
	Nop( 0x6FCE91, 2 );


	// Fixes for CBasePool misuse (object/projectile pools)
	{
		// Poor man's jitasm ;)
		auto pushEax = []( uintptr_t& addr )
		{
			Patch<uint8_t>( addr, 0x50 );
			addr += 1;
		};

		auto pushEbx = []( uintptr_t& addr )
		{
			Patch<uint8_t>( addr, 0x53 );
			addr += 1;
		};

		auto pushEsi = []( uintptr_t& addr )
		{
			Patch<uint8_t>( addr, 0x56 );
			addr += 1;
		};

		auto pushEdi = []( uintptr_t& addr )
		{
			Patch<uint8_t>( addr, 0x57 );
			addr += 1;
		};

		auto movEcxEbx = []( uintptr_t& addr )
		{
			Patch( addr, { 0x8B, 0xCB } );
			addr += 2;
		};

		auto movEcxEbp = []( uintptr_t& addr )
		{
			Patch( addr, { 0x8B, 0xCD } );
			addr += 2;
		};

		auto movEcxEsi = []( uintptr_t& addr )
		{
			Patch( addr, { 0x8B, 0xCE } );
			addr += 2;
		};

		auto movEcxEdi = []( uintptr_t& addr )
		{
			Patch( addr, { 0x8B, 0xCF } );
			addr += 2;
		};

		auto movEsiEax = []( uintptr_t& addr )
		{
			Patch( addr, { 0x8B, 0xF0 } );
			addr += 2;
		};

		auto movEdiEax = []( uintptr_t& addr )
		{
			Patch( addr, { 0x8B, 0xF8 } );
			addr += 2;
		};

		auto call = []( uintptr_t& addr, auto dest )
		{
			InjectHook( addr, dest, PATCH_CALL );
			addr += 5;
		};

		auto jmp = []( uintptr_t& addr, uintptr_t dest )
		{
			const ptrdiff_t offset = dest - (addr+2);
			if ( offset >= INT8_MIN && offset <= INT8_MAX )
			{
				Patch( addr, { 0xEB, static_cast<uint8_t>(offset) } );
				addr += 2;
			}
			else
			{
				InjectHook( addr, dest, PATCH_JUMP );
				addr += 5;
			}
		};

		InjectHook( 0x435BD0, &CBasePool::GetSlotWithLinked, PATCH_JUMP );
		InjectHook( 0x436B90, &CBasePool::GetSlotWithLinkedWrapper, PATCH_JUMP );

		uintptr_t address;

		address = 0x4378D0;
		pushEdi( address );
		movEcxEbx( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x437901 );

		address = 0x437A18;
		pushEdi( address );
		movEcxEbx( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x437A59 );

		address = 0x437AA4;
		pushEsi( address );
		movEcxEdi( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		jmp( address, 0x437AD3 );

		address = 0x44A4F6;
		pushEdi( address );
		movEcxEbx( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x44A527 );

		address = 0x450A99;
		pushEsi( address );
		movEcxEbx( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		jmp( address, 0x450AC5 );

		address = 0x45E72B;
		pushEsi( address );
		movEcxEdi( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		jmp( address, 0x45E757 );

		address = 0x49E0D4;
		pushEdi( address );
		movEcxEbx( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x49E109 );

		address = 0x49E489;
		pushEbx( address );
		movEcxEdi( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x49E4B8 );

		address = 0x4CFE11;
		pushEdi( address );
		movEcxEbp( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x4CFE43 );

		address = 0x4CFE91;
		pushEdi( address );
		movEcxEbp( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x4CFEC3 );

		address = 0x4CFF24;
		pushEbx( address );
		movEcxEdi( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x4CFF59 );
	
		address = 0x4D0138;
		pushEdi( address );
		movEcxEbx( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x4D0169 );

		address = 0x4D01A0;
		pushEdi( address );
		movEcxEbx( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x4D01D1 );
	
		address = 0x4D0211;
		pushEdi( address );
		movEcxEbp( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x4D0243 );

		address = 0x4D02B0;
		pushEdi( address );
		movEcxEbp( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x4D02E2 );

		address = 0x4D0350;
		pushEsi( address );
		movEcxEdi( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		jmp( address, 0x4D037F );

		address = 0x5309A6;
		pushEdi( address );
		movEcxEbp( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x5309D5 );

		address = 0x532446;
		pushEsi( address );
		movEcxEdi( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		jmp( address, 0x532472 );

		address = 0x5332DA;
		pushEbx( address );
		movEcxEdi( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x53330C );

		address = 0x5BCE62;
		pushEdi( address );
		movEcxEbx( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x5BCE97 );

		address = 0x5C2642;
		pushEbx( address );
		movEcxEbp( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEdiEax( address );
		jmp( address, 0x5C2679 );

		address = 0x5C2770;
		pushEbx( address );
		movEcxEbp( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEdiEax( address );
		jmp( address, 0x5C27A7 );

		address = 0x5C2FC6;
		pushEdi( address );
		movEcxEsi( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		jmp( address, 0x5C2FF3 );

		address = 0x5C31F0;
		pushEdi( address );
		movEcxEsi( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		jmp( address, 0x5C3220 );

		address = 0x5C3280;
		pushEsi( address );
		movEcxEdi( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		jmp( address, 0x5C32AF );

		address = 0x5C33D6;
		pushEdi( address );
		movEcxEbx( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x5C3407 );

		address = 0x5C4D91;
		pushEdi( address );
		movEcxEbp( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x5C4DC3 );

		address = 0x677206;
		pushEdi( address );
		movEcxEbx( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		jmp( address, 0x67722E );

		address = 0x67C1AD;
		pushEdi( address );
		movEcxEbx( address );
		call( address, &CBasePool::GetSlotWithLinkedWrapper );
		movEsiEax( address );
		jmp( address, 0x67C1F2 );
	}

	// Don't fail if call to CoInitializeEx didn't return S_TRUE (maybe something else called CoInitializeEx on us already)
	Nop( 0x5AE2B4, 6 );

	
	// Version number with SP build in main menu
	Patch<const char*>( 0x6A69EA + 1, "%1.3f SP Build " STRINGIZE(SILENTPATCH_REVISION_ID) );


	// Fix heap corruptions on exit
	{
		using namespace DoubleFreeOnExitFix;

		InjectHook( 0x519090, ReleaseStruct, PATCH_JUMP );

		Patch<uint8_t>( 0x55E0E2, 0x56 ); // push esi
		InjectHook( 0x55E0E3, ReleaseTextureAndNull );

		// Series of identical calls to patch...
		auto fixEax = []( uintptr_t& addr, uintptr_t extra = 0 )
		{
			Patch( addr, { 0xB8 } );
			addr += 5 + 1 + extra;
			InjectHook( addr, DoubleFreeOnExitFix::ReleaseTextureAndNull );
			addr += 5;
		};

		auto fixEcx = []( uintptr_t& addr, uintptr_t extra = 0 )
		{
			Patch( addr, { 0x90, 0xB9 } );
			addr += 6 + 1 + extra;
			InjectHook( addr, DoubleFreeOnExitFix::ReleaseTextureAndNull );
			addr += 5;
		};

		auto fixEdx = []( uintptr_t& addr, uintptr_t extra = 0 )
		{
			Patch( addr, { 0x90, 0xBA } );
			addr += 6 + 1 + extra;
			InjectHook( addr, DoubleFreeOnExitFix::ReleaseTextureAndNull );
			addr += 5;
		};

		uintptr_t address = 0x528622;
		fixEdx( address );
		fixEax( address );
		fixEcx( address );

		fixEdx( address );
		fixEax( address );
		fixEcx( address );

		fixEdx( address );
		fixEax( address );
		fixEcx( address );

		fixEdx( address );
		fixEax( address );
		fixEcx( address );

		fixEdx( address );
		fixEax( address );
		fixEcx( address );

		// add esp in code...
		fixEdx( address );
		fixEax( address, 3 );
		fixEcx( address );

		fixEdx( address );
		fixEax( address );
		fixEcx( address );

		fixEdx( address );
		fixEax( address );


		// Missing reference adding...
		ReadCall( 0x514D98, orgPopTimer );
		InjectHook( 0x514D98, PopTimer_AddMissingReferences );

		// TEMPORARY DEBUG
		//InjectHook( 0x5F0F90, ReleaseTextureDebug, PATCH_JUMP );
	}

	// Don't call RwFrameDestroy from CameraDestroy (crashes for some reason)
	Patch<uint8_t>( 0x5EF954, 0xEB );
}

static void ProcHook()
{
	static bool		bPatched = false;
	if ( !bPatched )
	{
		bPatched = true;

		InjectHooks();
	}
}

static uint8_t orgCode[5];
static decltype(SystemParametersInfoA)* pOrgSystemParametersInfoA;
BOOL WINAPI SystemParametersInfoA_Hook( UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni )
{
	ProcHook();
	return pOrgSystemParametersInfoA( uiAction, uiParam, pvParam, fWinIni );
}

BOOL WINAPI SystemParametersInfoA_OverwritingHook( UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni )
{
	Memory::VP::Patch( pOrgSystemParametersInfoA, { orgCode[0], orgCode[1], orgCode[2], orgCode[3], orgCode[4] } );
	return SystemParametersInfoA_Hook( uiAction, uiParam, pvParam, fWinIni );
}

static bool PatchIAT()
{
	HINSTANCE					hInstance = GetModuleHandle(nullptr);
	PIMAGE_NT_HEADERS			ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hInstance + ((PIMAGE_DOS_HEADER)hInstance)->e_lfanew);

	// Find IAT	
	PIMAGE_IMPORT_DESCRIPTOR	pImports = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hInstance + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// Find user32.dll
	for ( ; pImports->Name != 0; pImports++ )
	{
		if ( !_stricmp((const char*)((DWORD_PTR)hInstance + pImports->Name), "USER32.DLL") )
		{
			if ( pImports->OriginalFirstThunk != 0 )
			{
				PIMAGE_IMPORT_BY_NAME*		pFunctions = (PIMAGE_IMPORT_BY_NAME*)((DWORD_PTR)hInstance + pImports->OriginalFirstThunk);

				// user32.dll found, find SystemParametersInfoA
				for ( ptrdiff_t j = 0; pFunctions[j] != nullptr; j++ )
				{
					if ( !strcmp((const char*)((DWORD_PTR)hInstance + pFunctions[j]->Name), "SystemParametersInfoA") )
					{
						// Overwrite the address with the address to a custom SystemParametersInfoA
						DWORD			dwProtect[2];
						DWORD_PTR*		pAddress = &((DWORD_PTR*)((DWORD_PTR)hInstance + pImports->FirstThunk))[j];

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
	memcpy( orgCode, pOrgSystemParametersInfoA, sizeof(orgCode) );
	Memory::VP::InjectHook( pOrgSystemParametersInfoA, SystemParametersInfoA_OverwritingHook, PATCH_JUMP );
	return true;
}

static void InstallHooks()
{
	bool getStartupInfoHooked = PatchIAT();
	if ( !getStartupInfoHooked )
	{
		PatchIAT_ByPointers();
	}
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	UNREFERENCED_PARAMETER(hinstDLL);
	UNREFERENCED_PARAMETER(lpvReserved);

	if ( fdwReason == DLL_PROCESS_ATTACH )
	{
		hDLLModule = hinstDLL;
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
		if ( _InterlockedCompareExchange( &InitCount, 1, 0 ) != 0 ) return;
		InstallHooks();
	}
}