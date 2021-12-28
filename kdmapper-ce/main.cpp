#include "pch.h"
#include "kdmapper-ce.hpp"

int wmain(const int argc, wchar_t** argv) {

#if _DEBUG
	Log("Debug Mode Enable\n");
#endif

	wchar_t DriverFullPath[MAX_PATH] = { 0 };
	const wchar_t* DriverName = argv[1];
	HANDLE hDriver = NULL;
	utils::KdmapperInit();

	// TODO: �R�}���h���C�������ɗ^����ꂽ�t�@�C�����������Ƀ��[�h
	if (argc < 2) {
		Error("Usage: kdmapper-ce.exe <driver_path>");
		return -1;
	}

	// reflective���[�h�����h���C�o�̃t���p�X���擾

	if (!_wfullpath(DriverFullPath, DriverName, MAX_PATH)) {
		Error("_wfullpath failed");
		return -1;
	}

	hDriver = utils::ReadFileToMemory(DriverFullPath);
	if (hDriver == INVALID_HANDLE_VALUE) {
		Error("ReadFileToMemory failed");
		return -1;
	}
		
	// TODO: dbk64�t�@�C�����f�B�X�N�Ƀh���b�v
	// TODO: �T�[�r�X�̍쐬�C�J�n
	// TODO: �h���b�v����dbk64�t�@�C�����폜
	// TODO: kernelmoduleunloader�ɃV�F���R�[�h���C���W�F�N�g���Cdbk64�T�[�r�X�̃n���h�����擾
	// TODO: DeviceIoControl���g���h���C�o�����[�h
	// TODO: �T�[�r�X�̒�~�C�폜
	
	getchar();
	return 0;
}
