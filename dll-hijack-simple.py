#!/usr/bin/env python3

import os
import sys
import time
import pefile
import traceback

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
    for sym in symbols:
        exports.append('extern "C" __declspec(dllexport) void %s() {}' % (sym.name.decode('latin1')))

    with open(filename, 'w+') as f:
        f.write(template + '\n'.join(exports) + '\n')

if __name__ == '__main__':
    if len(sys.argv) == 1:
        print ('Usage:', sys.argv[0], 'a.dll b.dll ...')
        sys.exit(0)

    for arg in sys.argv[1:]:
        pe       = pefile.PE(arg)
        filename = os.path.basename(arg) + '.cpp'

        generate(filename, pe.DIRECTORY_ENTRY_EXPORT.symbols)
        print('Wrote', filename)
