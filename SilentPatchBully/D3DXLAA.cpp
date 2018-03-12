#include "MemoryMgr.h"
#include <d3dx9shader.h>

#pragma comment(lib, "d3dx9.lib")

HRESULT WINAPI D3DXCompileShader_LAA(LPCSTR pSrcData, UINT srcDataLen, const D3DXMACRO *pDefines, LPD3DXINCLUDE pInclude, LPCSTR pFunctionName, LPCSTR pProfile, DWORD Flags,
									LPD3DXBUFFER *ppShader, LPD3DXBUFFER *ppErrorMsgs, LPD3DXCONSTANTTABLE *ppConstantTable)
{
	HRESULT hr = D3DXCompileShader( pSrcData, srcDataLen, pDefines, pInclude, pFunctionName, pProfile, Flags, ppShader, ppErrorMsgs, nullptr );
	if ( ppConstantTable != nullptr && SUCCEEDED(hr) )
	{
		hr = D3DXGetShaderConstantTableEx( static_cast<DWORD*>((*ppShader)->GetBufferPointer()), D3DXCONSTTABLE_LARGEADDRESSAWARE, ppConstantTable );
	}
	return hr;
}

HRESULT WINAPI D3DXCompileShaderFromFileA_LAA(LPCSTR pSrcFile, const D3DXMACRO *pDefines, LPD3DXINCLUDE pInclude, LPCSTR pFunctionName, LPCSTR pProfile, DWORD Flags,
									LPD3DXBUFFER *ppShader, LPD3DXBUFFER *ppErrorMsgs, LPD3DXCONSTANTTABLE *ppConstantTable)
{
	HRESULT hr = D3DXCompileShaderFromFileA(pSrcFile, pDefines, pInclude, pFunctionName, pProfile, Flags, ppShader, ppErrorMsgs, ppConstantTable);
	if ( ppConstantTable != nullptr && SUCCEEDED(hr) )
	{
		hr = D3DXGetShaderConstantTableEx( static_cast<DWORD*>((*ppShader)->GetBufferPointer()), D3DXCONSTTABLE_LARGEADDRESSAWARE, ppConstantTable );
	}
	return hr;
}

HRESULT WINAPI
D3DXCreateEffect_LAA(LPDIRECT3DDEVICE9 pDevice, LPCVOID pSrcData, UINT SrcDataLen, CONST D3DXMACRO* pDefines, LPD3DXINCLUDE pInclude, DWORD Flags,
					LPD3DXEFFECTPOOL pPool, LPD3DXEFFECT* ppEffect, LPD3DXBUFFER* ppCompilationErrors)
{
	return D3DXCreateEffect( pDevice, pSrcData, SrcDataLen, pDefines, pInclude, Flags | D3DXFX_LARGEADDRESSAWARE, pPool, ppEffect, ppCompilationErrors );
}

void InjectFixedD3DXFuncs()
{
	using namespace Memory;

	InjectHook( 0x85AC96, D3DXCompileShader_LAA, PATCH_JUMP );
	InjectHook( 0x8D85CC, D3DXCompileShaderFromFileA_LAA, PATCH_JUMP );
	InjectHook( 0x85AC8A, D3DXCreateEffect_LAA, PATCH_JUMP );
}