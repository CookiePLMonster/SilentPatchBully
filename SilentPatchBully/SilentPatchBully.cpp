#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#define WINVER 0x0502
#define _WIN32_WINNT 0x0502

#include <windows.h>
#include "MemoryMgr.h"

#include <cassert>

/*__declspec(naked) void* orgMalloc( size_t size )
{
	_asm
	{
		cmp byte ptr ds:[0D1416Ch], 0
		push 5EE837h
		retn
	}
}

__declspec(naked) void orgFree( void* data )
{
	_asm
	{
		mov     eax, [esp+4]
		test    eax, eax
		push 5EE946h
		retn
	}
}*/

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

	//static const uint64_t sneakyAllocation = 0xBAADF00DBEEF6996;
	/*void* MemoryMgrMalloc( size_t size )
	{
		//size *= 8;

		/*if ( size == 0 )
		{
			// You sneaky fuck
			return (void*)&sneakyAllocation;
		}
		return orgMalloc( size );*/

	/*	// Their malloc is actually calloc, as allocated memory gets zeroed
		return calloc( size, 1 );
		//auto mem = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, size );
		//return mem;
	}

	void MemoryMgrFree( void* data )
	{
		/*if ( data != &sneakyAllocation )
		{
			orgFree( data );
		}*/

	/*	if ( data != nullptr /*&& data != &sneakyAllocatio*///n )
/*		{
			//HeapFree( GetProcessHeap(), 0, data );
			free( data );
		}
	}*/

	void* MemoryMgrMalloc( size_t size )
	{
		if ( size == 0 )
		{
			return nullptr;
		}

		//size *= 8;

		/*if ( size == 0 )
		{
			// You sneaky fuck
			return (void*)&sneakyAllocation;
		}*/

		// Their malloc is actually calloc, as allocated memory gets zeroed
		return calloc( size, 1 );
		//auto mem = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, size );
		//return mem;
	}

	void MemoryMgrFree( void* data )
	{
		if ( data != nullptr /*&& data != &sneakyAllocation */)
		{
			//HeapFree( GetProcessHeap(), 0, data );
			free( data );
		}
	}

	void* RwMallocAlign( size_t size, size_t align )
	{
		if ( size == 0 )
		{
			return nullptr;
		}

		// Based on CMemoryMgr::MallocAlign from GTA SA
		//uintptr_t mem = (uintptr_t)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, size + align );
		uintptr_t mem = reinterpret_cast<uintptr_t>(malloc( size + align ));
		uintptr_t memAligned = ( mem + align ) & ~(align - 1);

		uintptr_t* spaceForRealPtr = reinterpret_cast<uintptr_t*>(memAligned) - 1;
		*spaceForRealPtr = mem;
		return reinterpret_cast<void*>(memAligned);
	}

	void RwFreeAlign( void* data )
	{
		uintptr_t* spaceForRealPtr = static_cast<uintptr_t*>(data) - 1;
		//HeapFree( GetProcessHeap(), 0, reinterpret_cast<void*>(*spaceForRealPtr) );
		free( reinterpret_cast<void*>(*spaceForRealPtr) );
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

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	UNREFERENCED_PARAMETER(hinstDLL);
	UNREFERENCED_PARAMETER(lpvReserved);

	if ( fdwReason == DLL_PROCESS_ATTACH )
	{
		using namespace Memory;
		std::unique_ptr<ScopedUnprotect::Unprotect> Protect = ScopedUnprotect::UnprotectSectionOrFullModule( GetModuleHandle( nullptr ), ".text" );

		// Replaced custom CMemoryHeap with regular CRT functions (like in GTA)
		{
			using namespace FixedAllocators;
			//ReadCall( 0x5EE830, orgMalloc );
			//ReadCall( 0x5EE940, orgFree );

			/*InjectHook( 0x5EE830, MemoryMgrMalloc, PATCH_JUMP );
			InjectHook( 0x5EE940, MemoryMgrFree, PATCH_JUMP );*/

			InjectHook( 0x5EE630, InitMemoryMgr, PATCH_JUMP );
			InjectHook( 0x5EE5A0, ShutDownMemoryMgr, PATCH_JUMP );		
			InjectHook( 0x5EE830, MemoryMgrMalloc, PATCH_JUMP );
			InjectHook( 0x5EE940, MemoryMgrFree, PATCH_JUMP );
			InjectHook( 0x5EE9C0, RwMallocAlign, PATCH_JUMP );
			// 0x5EEA50 - RwMemoryMgrMalloc - jumps to MemoryMgrMalloc
			// 0x5EEA60 - RwMemoryMgrFree - jumps to MemoryMgrFree
			InjectHook( 0x5EEA70, RwFreeAlign, PATCH_JUMP );

			// TODO: Lua functions
			InjectHook( 0x5EEEF0, MemoryHeap_Free, PATCH_JUMP );
			InjectHook( 0x5EF4D0, MemoryHeap_MoveMemoryBully, PATCH_JUMP );

			// TODO: We can track memory a bit to make this function return somewhat accurate data
			InjectHook( 0x5EEDD0, MemoryHeap_GetMemoryUsed, PATCH_JUMP );

			// Fixed CPedType::Shutdown (zero pointers to prevent a double free)
			Patch<uint8_t>( 0x499CD8, 0x56 );
			InjectHook( 0x499CD9, OperatorDelete_Safe );

			// Write a pointer to fake 'upper memory bound' so CStreaming::MakeSpaceFor is pleased
			static const uintptr_t FAKE_MAX_MEMORY = 0x7FFFFFFF;
			Patch( 0xD141A8, &FAKE_MAX_MEMORY );
		}

		// Remove FILE_FLAG_NO_BUFFERING from CdStreams
		Patch<uint32_t>( 0x73ABEA + 6, FILE_FLAG_OVERLAPPED );
	}
	return TRUE;
}