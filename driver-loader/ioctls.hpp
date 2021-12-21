#pragma once
#define IOCTL_UNKNOWN_BASE					FILE_DEVICE_UNKNOWN
#define IOCTL_ALLOCATEMEM_NONPAGED    CTL_CODE(IOCTL_UNKNOWN_BASE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FREE_NONPAGED    CTL_CODE(IOCTL_UNKNOWN_BASE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GETPROCADDRESS		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_WRITEMEMORY		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0803, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_READMEMORY		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0804, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_EXECUTE_CODE		CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0805, METHOD_BUFFERED, FILE_WRITE_ACCESS)