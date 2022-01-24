#pragma once
#include <stdint.h>

namespace shellcode_resource
{
    static const uint8_t shellcode[] = {
	
	0x55, 0x8b, 0xec, 0x81, 0xec, 0xc0, 0x00, 0x00, 0x00, 0x89, 0x8d, 0x60, 0xff, 0xff, 0xff, 0x33, 
	0xc0, 0xc7, 0x45, 0xd4, 0x43, 0x72, 0x65, 0x61, 0x88, 0x45, 0xd2, 0x88, 0x45, 0xbe, 0x66, 0x89, 
	0x85, 0x5c, 0xff, 0xff, 0xff, 0x88, 0x45, 0xf6, 0x64, 0xa1, 0x30, 0x00, 0x00, 0x00, 0xc7, 0x45, 
	0xd8, 0x74, 0x65, 0x46, 0x69, 0xc7, 0x45, 0xdc, 0x6c, 0x65, 0x57, 0x00, 0xc7, 0x45, 0xc0, 0x4f, 
	0x75, 0x74, 0x70, 0xc7, 0x45, 0xc4, 0x75, 0x74, 0x44, 0x65, 0xc7, 0x45, 0xc8, 0x62, 0x75, 0x67, 
	0x53, 0xc7, 0x45, 0xcc, 0x74, 0x72, 0x69, 0x6e, 0x66, 0xc7, 0x45, 0xd0, 0x67, 0x41, 0xc7, 0x45, 
	0xe0, 0x53, 0x6c, 0x65, 0x65, 0x66, 0xc7, 0x45, 0xe4, 0x70, 0x00, 0xc7, 0x85, 0x68, 0xff, 0xff, 
	0xff, 0x48, 0x65, 0x6c, 0x6c, 0xc7, 0x85, 0x6c, 0xff, 0xff, 0xff, 0x6f, 0x20, 0x66, 0x72, 0xc7, 
	0x85, 0x70, 0xff, 0xff, 0xff, 0x6f, 0x6d, 0x20, 0x4b, 0xc7, 0x85, 0x74, 0xff, 0xff, 0xff, 0x65, 
	0x72, 0x6e, 0x65, 0xc7, 0x85, 0x78, 0xff, 0xff, 0xff, 0x6c, 0x4d, 0x6f, 0x64, 0xc7, 0x85, 0x7c, 
	0xff, 0xff, 0xff, 0x75, 0x6c, 0x65, 0x55, 0xc7, 0x45, 0x80, 0x6e, 0x6c, 0x6f, 0x61, 0xc7, 0x45, 
	0x84, 0x64, 0x65, 0x72, 0x2e, 0xc7, 0x45, 0x88, 0x65, 0x78, 0x65, 0x20, 0xc7, 0x45, 0x8c, 0x70, 
	0x72, 0x6f, 0x63, 0xc7, 0x45, 0x90, 0x65, 0x73, 0x73, 0x00, 0xc7, 0x45, 0x94, 0x57, 0x61, 0x69, 
	0x74, 0xc7, 0x45, 0x98, 0x69, 0x6e, 0x67, 0x20, 0xc7, 0x45, 0x9c, 0x74, 0x6f, 0x20, 0x62, 0xc7, 
	0x45, 0xa0, 0x65, 0x20, 0x6b, 0x69, 0xc7, 0x45, 0xa4, 0x6c, 0x6c, 0x65, 0x64, 0x66, 0xc7, 0x45, 
	0xa8, 0x2e, 0x00, 0xc7, 0x45, 0xac, 0x43, 0x72, 0x65, 0x61, 0xc7, 0x45, 0xb0, 0x74, 0x65, 0x46, 
	0x69, 0xc7, 0x45, 0xb4, 0x6c, 0x65, 0x57, 0x20, 0xc7, 0x45, 0xb8, 0x46, 0x61, 0x69, 0x6c, 0x66, 
	0xc7, 0x45, 0xbc, 0x65, 0x64, 0x8b, 0x40, 0x0c, 0xc7, 0x85, 0x44, 0xff, 0xff, 0xff, 0x6b, 0x00, 
	0x65, 0x00, 0xc7, 0x85, 0x48, 0xff, 0xff, 0xff, 0x72, 0x00, 0x6e, 0x00, 0x8b, 0x48, 0x0c, 0xc7, 
	0x85, 0x4c, 0xff, 0xff, 0xff, 0x65, 0x00, 0x6c, 0x00, 0xc7, 0x85, 0x50, 0xff, 0xff, 0xff, 0x33, 
	0x00, 0x32, 0x00, 0xc7, 0x85, 0x54, 0xff, 0xff, 0xff, 0x2e, 0x00, 0x64, 0x00, 0xc7, 0x85, 0x58, 
	0xff, 0xff, 0xff, 0x6c, 0x00, 0x6c, 0x00, 0xc7, 0x45, 0xe8, 0x47, 0x65, 0x74, 0x50, 0xc7, 0x45, 
	0xec, 0x72, 0x6f, 0x63, 0x41, 0xc7, 0x45, 0xf0, 0x64, 0x64, 0x72, 0x65, 0x66, 0xc7, 0x45, 0xf4, 
	0x73, 0x73, 0x89, 0x4d, 0xfc, 0x85, 0xc9, 0x0f, 0x84, 0xc8, 0x01, 0x00, 0x00, 0x53, 0x56, 0x57, 
	0x83, 0x79, 0x18, 0x00, 0x0f, 0x84, 0xb8, 0x01, 0x00, 0x00, 0x8b, 0x41, 0x30, 0x89, 0x45, 0xf8, 
	0x85, 0xc0, 0x0f, 0x84, 0x7b, 0x00, 0x00, 0x00, 0x33, 0xf6, 0x66, 0x39, 0xb5, 0x44, 0xff, 0xff, 
	0xff, 0x74, 0x59, 0x33, 0xc9, 0x8d, 0x3c, 0x01, 0x0f, 0xb7, 0x07, 0x66, 0x85, 0xc0, 0x74, 0x46, 
	0x8d, 0x9d, 0x44, 0xff, 0xff, 0xff, 0x03, 0xd9, 0x0f, 0xb7, 0x13, 0x8d, 0x4a, 0xbf, 0x66, 0x83, 
	0xf9, 0x19, 0x77, 0x09, 0x8d, 0x4a, 0x20, 0x66, 0x89, 0x0b, 0x0f, 0xb7, 0xd1, 0x8d, 0x48, 0xbf, 
	0x66, 0x83, 0xf9, 0x19, 0x77, 0x09, 0x83, 0xc0, 0x20, 0x66, 0x89, 0x07, 0x0f, 0xb7, 0xc0, 0x66, 
	0x3b, 0xd0, 0x75, 0x12, 0x8b, 0x45, 0xf8, 0x46, 0x8d, 0x0c, 0x36, 0x66, 0x83, 0xbc, 0x0d, 0x44, 
	0xff, 0xff, 0xff, 0x00, 0x75, 0xaf, 0x8b, 0x45, 0xf8, 0x8b, 0x4d, 0xfc, 0x66, 0x83, 0xbc, 0x75, 
	0x44, 0xff, 0xff, 0xff, 0x00, 0x75, 0x07, 0x66, 0x83, 0x3c, 0x70, 0x00, 0x74, 0x14, 0x8b, 0x09, 
	0x89, 0x4d, 0xfc, 0x85, 0xc9, 0x0f, 0x85, 0x65, 0xff, 0xff, 0xff, 0x5f, 0x5e, 0x5b, 0x8b, 0xe5, 
	0x5d, 0xc3, 0x8b, 0x79, 0x18, 0x85, 0xff, 0x0f, 0x84, 0x15, 0x01, 0x00, 0x00, 0xb8, 0x4d, 0x5a, 
	0x00, 0x00, 0x66, 0x39, 0x07, 0x0f, 0x85, 0x07, 0x01, 0x00, 0x00, 0x8b, 0x47, 0x3c, 0x8b, 0x44, 
	0x38, 0x78, 0x85, 0xc0, 0x0f, 0x84, 0xf8, 0x00, 0x00, 0x00, 0x8b, 0x4c, 0x07, 0x1c, 0x33, 0xf6, 
	0x8b, 0x54, 0x07, 0x18, 0x89, 0x4d, 0xf8, 0x8b, 0x4c, 0x07, 0x20, 0x8b, 0x44, 0x07, 0x24, 0x89, 
	0x95, 0x40, 0xff, 0xff, 0xff, 0x85, 0xd2, 0x0f, 0x84, 0xd5, 0x00, 0x00, 0x00, 0x03, 0xc7, 0x8d, 
	0x1c, 0x39, 0x89, 0x45, 0xfc, 0x0f, 0xb7, 0x00, 0x8b, 0x4d, 0xf8, 0x8b, 0x13, 0x03, 0xd7, 0x8d, 
	0x04, 0x81, 0x03, 0xc7, 0x89, 0x85, 0x64, 0xff, 0xff, 0xff, 0x33, 0xc0, 0x8d, 0x64, 0x24, 0x00, 
	0x8a, 0x0c, 0x02, 0x84, 0xc9, 0x74, 0x0e, 0x38, 0x4c, 0x05, 0xe8, 0x75, 0x08, 0x40, 0x80, 0x7c, 
	0x05, 0xe8, 0x00, 0x75, 0xeb, 0x80, 0x7c, 0x05, 0xe8, 0x00, 0x75, 0x06, 0x80, 0x3c, 0x10, 0x00, 
	0x74, 0x1c, 0x8b, 0x45, 0xfc, 0x46, 0x83, 0xc0, 0x02, 0x83, 0xc3, 0x04, 0x89, 0x45, 0xfc, 0x3b, 
	0xb5, 0x40, 0xff, 0xff, 0xff, 0x72, 0xae, 0x5f, 0x5e, 0x5b, 0x8b, 0xe5, 0x5d, 0xc3, 0x8b, 0x9d, 
	0x64, 0xff, 0xff, 0xff, 0x8b, 0x1b, 0x03, 0xdf, 0x74, 0x68, 0x8d, 0x45, 0xc0, 0x50, 0x57, 0xff, 
	0xd3, 0x89, 0x85, 0x64, 0xff, 0xff, 0xff, 0x8d, 0x45, 0xd4, 0x50, 0x57, 0xff, 0xd3, 0x8b, 0xf0, 
	0x8d, 0x45, 0xe0, 0x50, 0x57, 0xff, 0xd3, 0x8b, 0x9d, 0x64, 0xff, 0xff, 0xff, 0x8b, 0xf8, 0x8d, 
	0x85, 0x68, 0xff, 0xff, 0xff, 0x50, 0xff, 0xd3, 0x8b, 0x85, 0x60, 0xff, 0xff, 0xff, 0x6a, 0x00, 
	0x68, 0x80, 0x00, 0x00, 0x00, 0x6a, 0x03, 0x6a, 0x00, 0x6a, 0x03, 0x68, 0x00, 0x00, 0x00, 0xc0, 
	0x83, 0xc0, 0x04, 0x50, 0xff, 0xd6, 0x8b, 0x8d, 0x60, 0xff, 0xff, 0xff, 0x85, 0xc0, 0x89, 0x01, 
	0x8d, 0x45, 0xac, 0x74, 0x03, 0x8d, 0x45, 0x94, 0x50, 0xff, 0xd3, 0x68, 0x10, 0x27, 0x00, 0x00, 
	0xff, 0xd7, 0x5f, 0x5e, 0x5b, 0x8b, 0xe5, 0x5d, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc 
	
    };
}