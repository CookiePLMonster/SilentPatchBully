#ifndef __POOLS
#define __POOLS

#include <cstdint>

class CBasePool // Non-templated in Bully
{
private:
	uint8_t*	m_pSlots;
	union			tSlotInfos
	{
		struct
		{
			unsigned char	m_uID	: 7;
			bool			m_bFree	: 1;
		}				a;
		signed char		b;
	}*				m_pSlotInfos;
	int				m_nNumSlots;
	int				m_nSlotSize; // Added in Bully
	CBasePool*		m_pLinkedPool; // Added in Bully
	int				m_nFirstFree;
	bool			m_bOwnsAllocations;
	bool			m_bConstructData; // Added in Bully
	bool			m_bDealWithNoMemory;

public:
	int		GetSizeWithLinked() const
	{
		int size = m_nNumSlots;
		if ( m_pLinkedPool != nullptr )
		{
			size += m_pLinkedPool->GetSizeWithLinked();
		}
		return size;
	}

	void* GetSlotWithLinked(int index, bool checkFlags) const
	{
		if ( index < m_nNumSlots )
		{
			void* slot = m_pSlots + (index * m_nSlotSize);
			if ( checkFlags )
			{
				// Original game checks this for index >= m_nNumSlots too, creating an out-of-bounds-read bug
				if ( m_pSlotInfos[index].a.m_bFree )
				{
					slot = nullptr;
				}
			}
			return slot;
		}

		if ( m_pLinkedPool != nullptr )
		{
			return m_pLinkedPool->GetSlotWithLinked( index - m_nNumSlots, true );
		}
		return nullptr;
	}

	void* GetSlotWithLinkedWrapper(int index) const
	{
		return GetSlotWithLinked( index, true );
	}

};

static_assert(sizeof(CBasePool) == 0x1C, "Wrong size: CBasePool");

#endif