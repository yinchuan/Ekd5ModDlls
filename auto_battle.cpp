#include <Windows.h>
#include <malloc.h>
#include <string.h>
#include <iostream>

HANDLE ekd5Handle = GetCurrentProcess();
HANDLE hThread;
HINSTANCE hInst;

void codeCave(void *destinationAddress, void *patchedFunction, int mangledBytes) {
    int jmpLength = 5;
    int patchLength = jmpLength + mangledBytes;
    DWORD offset = ((DWORD) patchedFunction - (DWORD) destinationAddress) - jmpLength;
    BYTE *patch = (BYTE *) malloc(sizeof(BYTE) * patchLength);
    memset(patch, 0x90, patchLength); // fill up with nop
    patch[0] = 0xe8; // call rel32
    memcpy(patch + 1, &offset, jmpLength - 1);
    if (!WriteProcessMemory(ekd5Handle, destinationAddress, patch, patchLength, 0)) {
        MessageBoxA(nullptr, "fail to detour", "fail", MB_OK);
    } else {
        MessageBoxA(nullptr, "succeed to detour", "success", MB_OK);
    }
}

void attackInOurTurn() {
    int f;
    int caocaoAddr = 0x4B2C50;

    // get status of fang. the function to get status of fang is 0041DFB0
    if (*reinterpret_cast<byte *>(caocaoAddr + 0x19) == 3) {
        // 3 means not boosted, 6 means boosted
        // call baqi if not boosted
        __asm{
                push 0x3F // code for baqi
                mov ecx, caocaoAddr
                mov f, 0x43DC99
                call f // callee clean up
                }
    } else {
        // address 0x0043DB0E in 0x43dada(attack) calls a function to select target on screen
        // here we bypass the function, set its return value to eax
        // 0x23 is the first enemy in battle
        BYTE bypass[5] = {0xB8, 0x23, 00, 00, 00}; // mov eax, 0x23
        BYTE recover[5] = {0xE8, 0x2A, 0x78, 0x01, 0x00}; // original code
        if (!WriteProcessMemory(ekd5Handle, reinterpret_cast<void *>(0x0043DB0E), bypass, 5, nullptr)) {
            MessageBoxA(nullptr, "fail to replace", "failed", MB_OK);
        }

        // call attack
        __asm{
                mov ecx, caocaoAddr // argument to attack function
                mov f, 0x43dada // address of attack function
                call f; // no argument, no clean up
                }

        // recover the bypassed function call, not neccessary here, just for record
        if (!WriteProcessMemory(ekd5Handle, reinterpret_cast<void *>(0x0043DB0E), recover, 5, nullptr)) {
            MessageBoxA(nullptr, "fail to recover", "failed", MB_OK);
        }
    }

    // call ProcessBattleDataAfterAnActio, deal with dead characters
    __asm {
            mov ecx, 0x4B3D08
            mov f, 0x44CC03
            call f // no argument, no clean up
            }

    // run real StartOurTurn function, so we can sniff around to check result of previous code
    // only useful for debug
    // __asm{
    //         mov ecx, 0x4B3D08
    //         mov f, 0x44E0D9
    //         call f;
    //         }
}

DWORD WINAPI MainThread(LPVOID lpParam) {
    // replace the code at address 0x0044EE8D with a call to the given function
    codeCave(reinterpret_cast<void *>(0x0044EE8D), &attackInOurTurn, 0);

    while (true) {
        if (GetAsyncKeyState(VK_F7) & 0x80000) {
            // press key F7 to unload dll to update
            // compiler can't write to the dll file when it's opened in a process
            // note: the patched code is still there
            break;
        }

        Sleep(200);
    }

    MessageBoxA(nullptr, "dll unloaded", "notification", MB_OK);
    FreeLibraryAndExitThread(hInst, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ulReasonForCall, LPVOID lpReserved) {
    switch (ulReasonForCall) {
        case DLL_PROCESS_ATTACH:
            hInst = hModule;
        // MessageBoxA(nullptr, "DLL injected", "injected", MB_OK);
            hThread = CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
            break;
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        default:
            break;
    }
    return TRUE;
}
