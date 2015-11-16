/*
* This file is part of SzimatSzatyor.
*
* SzimatSzatyor is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.

* SzimatSzatyor is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.

* You should have received a copy of the GNU General Public License
* along with SzimatSzatyor.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "OpcodeMgr.h"
#include "CommandMgr.h"
#include "CliRunnable.h"
#include "ConsoleManager.h"
#include "HookManager.h"
#include "Sniffer.h"

// static member initilization
volatile bool* ConsoleManager::_sniffingLoopCondition = NULL;

// needed to correctly shutdown the sniffer
HINSTANCE instanceDLL = NULL;
// true when a SIGINT occured
volatile bool isSigIntOccured = false;

// global access to the build number
WORD buildNumber = 0;
HookEntry hookEntry;

// this function will be called when send called in the client
// client has thiscall calling convention
// that means: this pointer is passed via the ECX/RCX register
// fastcall convention means that the first 2 parameters is passed
// via ECX/RCX and EDX/RDX registers so the first param will be the this pointer and
// the second one is just a dummy (not used)
DWORD __fastcall SendHook(void* thisPTR, void*, CDataStore*, DWORD);

typedef DWORD(__thiscall *SendProto)(void*, void*, DWORD);

// address of WoW's send function
DWORD sendAddress = 0;
// global storage for the "the hooking" machine code which 
// hooks client's send function
BYTE machineCodeHookSend[JMP_INSTRUCTION_SIZE] = { 0 };
// global storage which stores the
// untouched first 5 bytes machine code from the client's send function
BYTE defaultMachineCodeSend[JMP_INSTRUCTION_SIZE] = { 0 };

// this function will be called when recv called in the client
DWORD __fastcall RecvHook_PostVanilla(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore);
DWORD __fastcall RecvHook_PostWotLK(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore, void* param3);
DWORD __fastcall RecvHook_PostWoD(void* thisPTR, void* dummy, void* param1, void* param2, CDataStore* dataStore, void* param4);

typedef DWORD(__thiscall *RecvProto3)(void*, void*, void*);
typedef DWORD(__thiscall *RecvProto4)(void*, void*, void*, void*);
typedef DWORD(__thiscall *RecvProto5)(void*, void*, void*, void*, void*);

// address of WoW's recv function
DWORD recvAddress = 0;
// global storage for the "the hooking" machine code which
// hooks client's recv function
BYTE machineCodeHookRecv[JMP_INSTRUCTION_SIZE] = { 0 };
// global storage which stores the
// untouched first 5 bytes machine code from the client's recv function
BYTE defaultMachineCodeRecv[JMP_INSTRUCTION_SIZE] = { 0 };

// these are false if "hook functions" don't called yet
// and they are true if already called at least once
bool sendInitialized = false;
bool recvInitialized = false;

// basically this method controls what the sniffer should do
// pretty much like a "main method"
DWORD MainThreadControl(LPVOID /* param */);

enum Expansions
{
    EXPANSION_NONE,
    EXPANSION_VANILLA,
    EXPANSION_TBC,
    EXPANSION_WOTLK,
    EXPANSION_CATA,
    EXPANSION_MOP,
    EXPANSION_WOD,
    MAX_EXPANSION
};

Expansions GetExpansion(unsigned int build);
DWORD GetReceiveHook(Expansions exp);

// entry point of the DLL
BOOL APIENTRY DllMain(HINSTANCE instDLL, DWORD reason, LPVOID /* reserved */)
{
    // called when the DLL is being loaded into the
    // virtual address space of the current process (where to be injected)
    if (reason == DLL_PROCESS_ATTACH)
    {
        instanceDLL = instDLL;
        // disables thread notifications (DLL_THREAD_ATTACH, DLL_THREAD_DETACH)
        DisableThreadLibraryCalls(instDLL);

        // creates a thread to execute within the
        // virtual address space of the calling process (WoW)
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&MainThreadControl, NULL, 0, NULL);
    }
    // the DLL is being unloaded
    else if (reason == DLL_PROCESS_DETACH)
    {
        // close the dump file
        sSniffer->CloseFileDump();

        // deallocates the console
        ConsoleManager::Destroy();
    }
    return TRUE;
}

DWORD MainThreadControl(LPVOID /* param */)
{
    // creates the console
    if (!ConsoleManager::Create(&isSigIntOccured))
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);

    // some info
    printf("Welcome to SzimatSzatyor2, a WoW injector sniffer.\n");
    printf("SzimatSzatyor2 is distributed under the GNU GPLv3 license.\n");
    printf("Source code is available at: ");
    printf("https://github.com/Zedron/SzimatSzatyor2\n\n");

    printf("Type quit to stop sniffing ");
    printf("Note: you can simply re-attach the sniffer without ");
    printf("restarting the WoW.\n\n");
    printf("This project is no longer supported! new project is located at https://github.com/Zedron/Whiff\n\n");

    // gets the build number
    buildNumber = GetBuildNumberFromProcess();
    // error occured
    if (!buildNumber)
    {
        printf("Can't determine build number.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("Detected build number: %hu\n", buildNumber);

    // checks this build is supported or not
    if (!GetOffsets(instanceDLL, buildNumber, &hookEntry))
    {
        printf("ERROR: This build number is not supported.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // get the base address of the current process
    DWORD baseAddress = (DWORD)GetModuleHandle(NULL);

    DWORD localeAddress = hookEntry.locale;
    std::string locale;

    if (localeAddress)
    {
        for (int i = 3; i >= 0; --i)
            locale += *(char*)(baseAddress + (localeAddress + i));

        printf("Detected client locale: %s\n", locale.c_str());
    }
    else
    {
        printf("Locale NOT detected (incorrect locale offset?)\n");
        locale = "enUnk";
    }

    // gets where is the DLL which injected into the client
    char dllPath[MAX_PATH] = { 0 };
    DWORD dllPathSize = GetModuleFileName((HMODULE)instanceDLL, dllPath, MAX_PATH);
    if (!dllPathSize)
    {
        printf("\nERROR: Can't get the injected DLL's location, ");
        printf("ErrorCode: %u\n\n", GetLastError());
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("\nDLL path: %s\n", dllPath);

    sSniffer->SetSnifferInfo(std::string(dllPath), locale, buildNumber);
    sOpcodeMgr->Initialize();
    sOpcodeMgr->LoadOpcodeFile(instanceDLL); // must be called after Initialize()
    sCommandMgr->InitCommands();

    // gets address of NetClient::Send2
    sendAddress = baseAddress + hookEntry.send_2;
    // hooks client's send function
    HookManager::Hook(sendAddress, (DWORD_PTR)SendHook, machineCodeHookSend, defaultMachineCodeSend);
    printf("Send is hooked.\n");

    // gets address of NetClient::ProcessMessage
    recvAddress = baseAddress + hookEntry.receive;

    // hooks client's recv function
    HookManager::Hook(recvAddress, (DWORD_PTR)GetReceiveHook(GetExpansion(buildNumber)), machineCodeHookRecv, defaultMachineCodeRecv);

    printf("Recv is hooked.\n");

    // Launch CliRunnable thread
    std::thread* cliThread = new std::thread(CliThread);
    sSniffer->SetCliThread(cliThread);

    // loops until SIGINT (CTRL-C) occurs or quit is called
    while (!isSigIntOccured && !Sniffer::IsStopped())
    {
        sSniffer->ProcessCliCommands();
        Sleep(50); // sleeps 50 ms to be nice
    }

    sSniffer->ShutdownCLIThread();
    sOpcodeMgr->ShutDown();
    sCommandMgr->ClearCommands();

    // unhooks functions
    HookManager::WriteBlock(sendAddress, defaultMachineCodeSend);
    HookManager::WriteBlock(recvAddress, defaultMachineCodeRecv);

    printf("Detached!\n");

    // shutdowns the sniffer
    // note: after that DLL's entry point will be called with
    // reason DLL_PROCESS_DETACH
    FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    return 0;
}

DWORD __fastcall SendHook(void* thisPTR, void* dummy , CDataStore* dataStore, DWORD connectionId)
{
    // dumps the packet
    sSniffer->DumpPacket(PacketInfo(CMSG, connectionId, 4, dataStore));

    // unhooks the send function
    HookManager::WriteBlock(sendAddress, defaultMachineCodeSend);

    // now let's call client's function
    // so it can send the packet to the server (connection, CDataStore*, 2)
    DWORD returnValue = SendProto(sendAddress)(thisPTR, dataStore, connectionId);

    // hooks again to catch the next outgoing packets also
    HookManager::WriteBlock(sendAddress, machineCodeHookSend);

    if (!sendInitialized)
    {
        printf("Send hook is working.\n");
        sendInitialized = true;
    }

    return 0;
}

#pragma region RecvHook

DWORD __fastcall RecvHook_PostVanilla(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore)
{
    // packet dump
    sSniffer->DumpPacket(PacketInfo(SMSG, 0, 2, dataStore));

    // unhooks the recv function
    HookManager::WriteBlock(recvAddress, defaultMachineCodeRecv);

    // calls client's function so it can processes the packet
    DWORD returnValue = RecvProto3(recvAddress)(thisPTR, param1, dataStore);

    // hooks again to catch the next incoming packets also
    HookManager::WriteBlock(recvAddress, machineCodeHookRecv);

    if (!recvInitialized)
    {
        printf("Recv hook3 is working.\n");
        recvInitialized = true;
    }

    return returnValue;
}

DWORD __fastcall RecvHook_PostWotLK(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore, void* param3)
{
    WORD opcodeSize = buildNumber <= WOW_MOP_16135 ? 2 : 4;
    // packet dump
    sSniffer->DumpPacket(PacketInfo(SMSG, (DWORD)param3, opcodeSize, dataStore));

    // unhooks the recv function
    HookManager::WriteBlock(recvAddress, defaultMachineCodeRecv);

    // calls client's function so it can processes the packet
    DWORD returnValue = RecvProto4(recvAddress)(thisPTR, param1, dataStore, param3);

    // hooks again to catch the next incoming packets also
    HookManager::WriteBlock(recvAddress, machineCodeHookRecv);

    if (!recvInitialized)
    {
        printf("Recv hook4 is working.\n");
        recvInitialized = true;
    }

    return returnValue;
}

DWORD __fastcall RecvHook_PostWoD(void* thisPTR, void* dummy, void* param1, void* param2, CDataStore* dataStore, void* param4)
{
    // packet dump
    sSniffer->DumpPacket(PacketInfo(SMSG, (DWORD)param4, 4, dataStore));

    // unhooks the recv function
    HookManager::WriteBlock(recvAddress, defaultMachineCodeRecv);

    // calls client's function so it can processes the packet
    DWORD returnValue = RecvProto5(recvAddress)(thisPTR, param1, param2, dataStore, param4);

    // hooks again to catch the next incoming packets also
    HookManager::WriteBlock(recvAddress, machineCodeHookRecv);

    if (!recvInitialized)
    {
        printf("Recv hook5 is working.\n");
        recvInitialized = true;
    }

    return returnValue;
}

#pragma endregion

DWORD GetReceiveHook(Expansions exp)
{
    switch (exp)
    {
        case EXPANSION_VANILLA:
        case EXPANSION_TBC:
            return (DWORD)RecvHook_PostVanilla;
            break;
        case EXPANSION_WOTLK:
        case EXPANSION_CATA:
        case EXPANSION_MOP:
            return (DWORD)RecvHook_PostWotLK;
            break;
        case EXPANSION_WOD:
            return (DWORD)RecvHook_PostWoD;
            break;
        default:
        {
            printf("\nERROR: Pre-release builds are not supported");
            system("pause");
            FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
        }
    }
}

Expansions GetExpansion(unsigned int build)
{
    // 6.0.2
    if (build >= 19033)
        return EXPANSION_WOD;

    // 5.0.4
    if (build >= 16016)
        return EXPANSION_MOP;

    // 4.0.1
    if (build >= 13164)
        return EXPANSION_CATA;

    // 3.0.2
    if (build >= 9056)
        return EXPANSION_WOTLK;

    // 2.0.1
    if (build >= 6180)
        return EXPANSION_TBC;

    // 1.1.0
    if (build >= 4044)
        return EXPANSION_VANILLA;

    return EXPANSION_NONE;
}
