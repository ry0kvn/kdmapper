import pefile
import mmap
import sys
import pprint

# VC++で以下のようにすると，特定の関数コードを指定したセグメント名で分離したバイナリが生成できる．
# extern "C" void PicStart(PVOID StartContext);
# #pragma alloc_text(".PIS", "PicStart")
# 
# これを利用して生成されたバイナリに対して，pefileを使って特定のセグメント名からコードを抽出し，
# シェルコードとして利用可能なヘッダとして出力する．


file_header = "\
#pragma once\n\
#include <stdint.h>\n\n\
namespace %s_resource\n\
{\n\
    static const uint8_t %s[] = {\n\
"

file_footer = "\
\n\
    };\n\
}\
"

def split_n(text, n):
    if len(text)%2 != 0:
        text += "0"
    return [ "0x" + text[i*n:i*n+n] + ", " for i in range(int(len(text)/n)) ]


def main(target_file, pic_path, pic_name) -> bool:
    status = False
    while True:
        try:
            # Map the executable in memory
            fd = open(target_file, 'rb')
            pe_data = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)
        except:
            print("[!]Failed to open target file")
            break

        try:
            # Parse the data contained in the buffer
            pe = pefile.PE(data=pe_data)
        except:
            print("[!]Failed to parse target file")
            break

        # pprint.pprint(dir(pe))

        if not pe.is_driver:
            print("[!]Invalid driver file was input")
            break

        print("e_magic value: %s" % hex(pe.DOS_HEADER.e_magic))
        print("Signature value: %s" % hex(pe.NT_HEADERS.Signature))
        
        PointerToRawData = 0x0
        SizeOfRawData = 0x0
        sec_count = 0
        for sec in pe.sections:
            if sec.Name == b'.PIS\x00\x00\x00\x00':
                # print(sec)
                sec_count += 1
                break

        # if (PointerToRawData == 0x0 and SizeOfRawData == 0x0):
        #     print("[!]Couldn't find the PIC")
        #     break

        print("PIC disk address: 0x%x (%d bytes)" % (sec.PointerToRawData, sec.SizeOfRawData))
        pic_bytearray = pe.sections[sec_count].get_data()
        # pic_bytearray = pe.get_data(PointerToRawData, SizeOfRawData)
        
        pic_hexadecimal_string = pic_bytearray.hex()

        # 0x48, 0x89, 0x4C, 0x24, のようなフォーマットに変換
        pic_array = split_n(pic_hexadecimal_string, 2)

        # 最初のret命令を検索
        ind = pic_array.index("0xc3, ")

        # 最後のret命令を検索
        target_value = "0xc3, "
        i = 0
        index_list = []
        while target_value in pic_array[i:]:
            i = pic_array.index(target_value, i)
            index_list.append(i)
            i += 1
        del_index = index_list[-1] + 1

        # ret命令以降は不要なので削除
        del pic_array[del_index::]

        # 16 bytesでalignment. 
        # 0xccで埋める
        size = len(pic_array)
        align_count = 16 - size % 16
        for i in range(align_count):
            pic_array.append("0xcc, ")

        # 末尾要素の,を削除
        pic_array[-1] = pic_array[-1].replace(',', '')

        # 16文字毎に改行文字とタブ文字を挿入
        pic_array.insert(0, "\t")
        for n in range(0, len(pic_array), 16):
            pic_array[n] += "\n\t"

        print("PIC size %d bytes" % len(pic_array))

        f_header = file_header % (pic_name, pic_name)
        pic_output_path = pic_path + pic_name + '_resource.hpp'
        # .hppとしてファイルに出力
        with open(pic_output_path, 'w') as f:
            f.write(f_header)
            f.writelines(pic_array)
            f.write(file_footer)
        
        print('PIC header successfully created -> %s' % pic_output_path)
        status = True
        break

    return status


# ビルド前イベント登録例:
# python.exe $(SolutionDir)shellcode\shellcode_generator.py $(OutDir)input.sys $(ProjectDir) shellcode
# python.exe $(SolutionDir)shellcode\shellcode_generator.py $(SolutionDir)\Release\shellcode.exe $(ProjectDir) shellcode
if __name__ == '__main__':

    print('\n=== PostBuildEvent Start ===')
    
    target_pe_path = sys.argv[1] 
    output_dir_path = sys.argv[2]
    output_pic_name = sys.argv[3]
    
    print("target_pe_path %s" % target_pe_path)
    print("output_dir_path %s" % output_dir_path)
    print("output_pic_name %s" % output_pic_name)

    res = main(target_pe_path, output_dir_path, output_pic_name)
    if not res:
        print('[!]PIC generation process failed')
    
    print('=== PostBuildEvent End ===\n')
