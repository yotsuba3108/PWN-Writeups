# 🚀 [Dreamhack] - Out of Bound

- **Category :** Pwnable
- **Technique :** Out_of_bound (OOP) / Arry Index Manipulation 
- **Author :** Noah 

---
## 1. Tổng quan & Cơ chế bảo vệ : 
- Tổng quan và kiểm tra file binary bằng `checksec` : 
```
Arch:     i386
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```
-  Tổng quan 