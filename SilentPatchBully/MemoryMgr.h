#ifndef __MEMORYMGR
#define __MEMORYMGR

// Switches:
// _MEMORY_NO_CRT - don't include anything "complex" like ScopedUnprotect or memset
// _MEMORY_DECLS_ONLY - don't include anything but macroes

#define WRAPPER __declspec(naked)
#define DEPRECATED __declspec(deprecated)
#define EAXJMP(a) { _asm mov eax, a _asm jmp eax }
#define VARJMP(a) { _asm jmp a }
#define WRAPARG(a) ((int)a)

#define NOVMT __declspec(novtable)
#define SETVMT(a) *((uintptr_t*)this) = (uintptr_t)a

#ifndef _MEMORY_DECLS_ONLY

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdint>
#include <cassert>

#ifndef _MEMORY_NO_CRT
#include <initializer_list>
#include <iterator>
#endif

enum
{
	PATCH_CALL,
	PATCH_JUMP
};

template<typename AT>
inline AT DynBaseAddress(AT address)
{
	return (ptrdiff_t)GetModuleHandle(nullptr) - 0x400000 + address;
}

namespace Memory
{
	template<typename T, typename AT>
	inline void		Patch(AT address, T value)
	{*(T*)address = value; }

#ifndef _MEMORY_NO_CRT
	template<typename AT>
	inline void		Patch(AT address, std::initializer_list<uint8_t> list )
	{
		uint8_t* const addr = (uint8_t*)address;
		std::copy( list.begin(), list.end(), stdext::make_checked_array_iterator(addr, list.size()) );
	}
#endif

	template<typename AT>
	inline void		Nop(AT address, size_t count)
#ifndef _MEMORY_NO_CRT
	{ memset((void*)address, 0x90, count); }
#else
	{ do {
		*(uint8_t*)address++ = 0x90;
	} while ( --count != 0 ); }
#endif

	template<typename Var, typename AT>
	inline void		WriteOffsetValue(AT address, Var var)
	{
		union member_cast
		{
			intptr_t addr;
			Var varPtr;
		} cast;
		static_assert( sizeof(cast.addr) == sizeof(cast.varPtr), "member_cast failure!" );
		cast.varPtr = var;

		intptr_t dstAddr = (intptr_t)address;
		*(int32_t*)dstAddr = static_cast<int32_t>(cast.addr - dstAddr - 4);
	}

	template<typename Var, typename AT>
	inline void		ReadOffsetValue(AT address, Var& var)
	{
		union member_cast
		{
			intptr_t addr;
			Var varPtr;
		} cast;
		static_assert( sizeof(cast.addr) == sizeof(cast.varPtr), "member_cast failure!" );

		intptr_t srcAddr = (intptr_t)address;
		cast.addr = srcAddr + 4 + *(int32_t*)srcAddr;
		var = cast.varPtr;
	}

	template<typename AT, typename Func>
	inline void		InjectHook(AT address, Func hook)
	{
		WriteOffsetValue( (intptr_t)address + 1, hook );
	}

	template<typename AT, typename Func>
	inline void		InjectHook(AT address, Func hook, unsigned int nType)
	{
		*(uint8_t*)address = nType == PATCH_JUMP ? 0xE9 : 0xE8;
		InjectHook(address, hook);
	}

	template<typename Func, typename AT>
	inline void		ReadCall(AT address, Func& func)
	{
		ReadOffsetValue( (intptr_t)address+1, func );
	}

	template<typename AT>
	inline void*	ReadCallFrom(AT address, ptrdiff_t offset = 0)
	{
		uintptr_t addr;
		ReadCall( address, addr );
		return reinterpret_cast<void*>( addr + offset );
	}

#ifndef _MEMORY_NO_CRT
	inline bool MemEquals(uintptr_t address, std::initializer_list<uint8_t> val)
	{
		const uint8_t* mem = reinterpret_cast<const uint8_t*>(address);
		return std::equal( val.begin(), val.end(), stdext::make_checked_array_iterator(mem, val.size()) );
	}
#endif

	template<typename AT>
	inline AT Verify(AT address, uintptr_t expected)
	{
		assert( uintptr_t(address) == expected );
		return address;
	}

	namespace DynBase
	{
		template<typename T, typename AT>
		inline void		Patch(AT address, T value)
		{
			Memory::Patch(DynBaseAddress(address), value);
		}

#ifndef _MEMORY_NO_CRT
		template<typename AT>
		inline void		Patch(AT address, std::initializer_list<uint8_t> list )
		{
			Memory::Patch(DynBaseAddress(address), std::move(list));
		}
#endif

		template<typename AT>
		inline void		Nop(AT address, size_t count)
		{
			Memory::Nop(DynBaseAddress(address), count);
		}

		template<typename AT, typename HT>
		inline void		InjectHook(AT address, HT hook)
		{
			Memory::InjectHook(DynBaseAddress(address), hook);
		}

		template<typename AT, typename HT>
		inline void		InjectHook(AT address, HT hook, unsigned int nType)
		{
			Memory::InjectHook(DynBaseAddress(address), hook, nType);
		}

		template<typename Func, typename AT>
		inline void		ReadCall(AT address, Func& func)
		{
			Memory::ReadCall(DynBaseAddress(address), func);
		}

		template<typename AT>
		inline void*	ReadCallFrom(AT address, ptrdiff_t offset = 0)
		{
			return Memory::ReadCallFrom(DynBaseAddress(address), offset);
		}

#ifndef _MEMORY_NO_CRT
		inline bool MemEquals(uintptr_t address, std::initializer_list<uint8_t> val)
		{
			return Memory::MemEquals(DynBaseAddress(address), std::move(val));
		}

		template<typename AT>
		inline AT Verify(AT address, uintptr_t expected)
		{
			return Memory::Verify(address, DynBaseAddress(expected));
		}
#endif
	};

	namespace VP
	{
		template<typename T, typename AT>
		inline void		Patch(AT address, T value)
		{
			DWORD		dwProtect[2];
			VirtualProtect((void*)address, sizeof(T), PAGE_EXECUTE_READWRITE, &dwProtect[0]);
			Memory::Patch( address, value );
			VirtualProtect((void*)address, sizeof(T), dwProtect[0], &dwProtect[1]);
		}

#ifndef _MEMORY_NO_CRT
		template<typename AT>
		inline void		Patch(AT address, std::initializer_list<uint8_t> list )
		{
			DWORD		dwProtect[2];
			VirtualProtect((void*)address, list.size(), PAGE_EXECUTE_READWRITE, &dwProtect[0]);
			Memory::Patch(address, std::move(list));
			VirtualProtect((void*)address, list.size(), dwProtect[0], &dwProtect[1]);
		}
#endif

		template<typename AT>
		inline void		Nop(AT address, size_t count)
		{
			DWORD		dwProtect[2];
			VirtualProtect((void*)address, count, PAGE_EXECUTE_READWRITE, &dwProtect[0]);
			Memory::Nop( address, count );
			VirtualProtect((void*)address, count, dwProtect[0], &dwProtect[1]);
		}

		template<typename AT, typename HT>
		inline void		InjectHook(AT address, HT hook)
		{
			DWORD		dwProtect[2];

			VirtualProtect((void*)((DWORD_PTR)address + 1), 4, PAGE_EXECUTE_READWRITE, &dwProtect[0]);
			Memory::InjectHook( address, hook );
			VirtualProtect((void*)((DWORD_PTR)address + 1), 4, dwProtect[0], &dwProtect[1]);
		}

		template<typename AT, typename HT>
		inline void		InjectHook(AT address, HT hook, unsigned int nType)
		{
			DWORD		dwProtect[2];

			VirtualProtect((void*)address, 5, PAGE_EXECUTE_READWRITE, &dwProtect[0]);
			Memory::InjectHook( address, hook, nType );
			VirtualProtect((void*)address, 5, dwProtect[0], &dwProtect[1]);
		}

		template<typename Func, typename AT>
		inline void		ReadCall(AT address, Func& func)
		{
			Memory::ReadCall(address, func);
		}

		template<typename AT>
		inline void*	ReadCallFrom(AT address, ptrdiff_t offset = 0)
		{
			return Memory::ReadCallFrom(address, offset);
		}

#ifndef _MEMORY_NO_CRT
		inline bool MemEquals(uintptr_t address, std::initializer_list<uint8_t> val)
		{
			return Memory::MemEquals(address, std::move(val));
		}
#endif

		template<typename AT>
		inline AT Verify(AT address, uintptr_t expected)
		{
			return Memory::Verify(address, expected);
		}

		namespace DynBase
		{
			template<typename T, typename AT>
			inline void		Patch(AT address, T value)
			{
				VP::Patch(DynBaseAddress(address), value);
			}

#ifndef _MEMORY_NO_CRT
			template<typename AT>
			inline void		Patch(AT address, std::initializer_list<uint8_t> list )
			{
				VP::Patch(DynBaseAddress(address), std::move(list));
			}
#endif

			template<typename AT>
			inline void		Nop(AT address, size_t count)
			{
				VP::Nop(DynBaseAddress(address), count);
			}

			template<typename AT, typename HT>
			inline void		InjectHook(AT address, HT hook)
			{
				VP::InjectHook(DynBaseAddress(address), hook);
			}

			template<typename AT, typename HT>
			inline void		InjectHook(AT address, HT hook, unsigned int nType)
			{
				VP::InjectHook(DynBaseAddress(address), hook, nType);
			}

			template<typename Func, typename AT>
			inline void		ReadCall(AT address, Func& func)
			{
				Memory::ReadCall(DynBaseAddress(address), func);
			}

			template<typename AT>
			inline void*	ReadCallFrom(AT address, ptrdiff_t offset = 0)
			{
				Memory::ReadCallFrom(DynBaseAddress(address), offset);
			}

#ifndef _MEMORY_NO_CRT
			inline bool MemEquals(uintptr_t address, std::initializer_list<uint8_t> val)
			{
				return Memory::MemEquals(DynBaseAddress(address), std::move(val));
			}
#endif

			template<typename AT>
			inline AT Verify(AT address, uintptr_t expected)
			{
				return Memory::Verify(address, DynBaseAddress(expected));
			}

		};
	};
};

#ifndef _MEMORY_NO_CRT

#include <forward_list>
#include <tuple>
#include <memory>

namespace ScopedUnprotect
{
	class Unprotect
	{
	public:
		~Unprotect()
		{
			for ( auto& it : m_queriedProtects )
			{
				DWORD dwOldProtect;
				VirtualProtect( std::get<0>(it), std::get<1>(it), std::get<2>(it), &dwOldProtect );
			}
		}

	protected:
		Unprotect() = default;

		void UnprotectRange( DWORD_PTR BaseAddress, SIZE_T Size )
		{
			SIZE_T QueriedSize = 0;
			while ( QueriedSize < Size )
			{
				MEMORY_BASIC_INFORMATION MemoryInf;
				DWORD dwOldProtect;

				VirtualQuery( (LPCVOID)(BaseAddress + QueriedSize), &MemoryInf, sizeof(MemoryInf) );
				if ( MemoryInf.State == MEM_COMMIT && (MemoryInf.Type & MEM_IMAGE) != 0 &&
					(MemoryInf.Protect & (PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY|PAGE_READWRITE|PAGE_WRITECOPY)) == 0 )
				{
					const bool wasExecutable = (MemoryInf.Protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ)) != 0;
					VirtualProtect( MemoryInf.BaseAddress, MemoryInf.RegionSize, wasExecutable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, &dwOldProtect );
					m_queriedProtects.emplace_front( MemoryInf.BaseAddress, MemoryInf.RegionSize, MemoryInf.Protect );
				}
				QueriedSize += MemoryInf.RegionSize;
			}
		}

	private:
		std::forward_list< std::tuple< LPVOID, SIZE_T, DWORD > >	m_queriedProtects;
	};

	class Section : public Unprotect
	{
	public:
		Section( HINSTANCE hInstance, const char* name )
		{
			PIMAGE_NT_HEADERS		ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hInstance + ((PIMAGE_DOS_HEADER)hInstance)->e_lfanew);
			PIMAGE_SECTION_HEADER	pSection = IMAGE_FIRST_SECTION(ntHeader);

			DWORD_PTR VirtualAddress = DWORD_PTR(-1);
			SIZE_T VirtualSize = SIZE_T(-1);
			for ( SIZE_T i = 0, j = ntHeader->FileHeader.NumberOfSections; i < j; ++i, ++pSection )
			{
				if ( strncmp( (const char*)pSection->Name, name, IMAGE_SIZEOF_SHORT_NAME ) == 0 )
				{
					VirtualAddress = (DWORD_PTR)hInstance + pSection->VirtualAddress;
					VirtualSize = pSection->Misc.VirtualSize;
					m_locatedSection = true;
					break;
				}
			}

			if ( VirtualAddress == DWORD_PTR(-1) )
				return;

			UnprotectRange( VirtualAddress, VirtualSize );
		};

		bool	SectionLocated() const { return m_locatedSection; }

	private:
		bool	m_locatedSection = false;
	};

	class FullModule : public Unprotect
	{
	public:
		FullModule( HINSTANCE hInstance )
		{
			PIMAGE_NT_HEADERS		ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hInstance + ((PIMAGE_DOS_HEADER)hInstance)->e_lfanew);
			UnprotectRange( (DWORD_PTR)hInstance, ntHeader->OptionalHeader.SizeOfImage );
		}
	};

	inline std::unique_ptr<Unprotect> UnprotectSectionOrFullModule( HINSTANCE hInstance, const char* name )
	{
		std::unique_ptr<Section> section = std::make_unique<Section>( hInstance, name );
		if ( !section->SectionLocated() )
		{
			return std::make_unique<FullModule>( hInstance );
		}
		return section;
	}
};

#endif

#endif

#endif