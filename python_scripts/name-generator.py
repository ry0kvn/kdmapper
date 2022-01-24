def name_gen(name):
    print("WCHAR " + name + "String[] " , end="")
    print("= {", end='')
    for n in name:
        print("'" + n+ "', ", end='')
    print("0};")

name = ["VirtualAlloc",
        "WriteProcessMemory",
        "GetCurrentProcess",
        "DbgPrint","Hello from Kernel mode shellcode!",
        "Shellcode successfully executed!",
        "\\driver\\EvilCEDRIVER73",
        "ObReferenceObjectByName",
        "ObfDereferenceObject",
        "\\Driver\\KernelPISCreator",
        "IoDriverObjectType",
        "funcAddr==NULL",
        "Hellor From MyDispatchIoctlDBVM",
        "[+]Waiting to be killed.",
        "Hello from KernelModuleUnloader.exe process",
        "Target driver object: 0x%p",
        "_InterlockedExchangePointer",
        "Target driver object name : 0x%ls",
        "IoCreateDriver",
        "ExAllocatePool",
        "RtlInitUnicodeString",
        "MmUnlockPages",
        "IoFreeMdl",
        "MmUnmapLockedPages",
        "MmUnlockPages",
        "PsLookupProcessByProcessId",
        "KeStackAttachProcess",
        "IoAllocateMdl",
        "MmProbeAndLockPages",
        "KeUnstackDetachProcess",
        "ObDereferenceObject",
        "MmMapLockedPagesSpecifyCache",
        "DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = 0x%p"
    ]
for n in name:
    name_gen(n)