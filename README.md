# DLL劫持代码生成器

读取DLL符号表，然后根据符号表生成可编译的DLL源代码。默认代码块为空，用户需要自行填充。

1. dll-hijack-simple.py: 直接覆盖目标方法，可以根据DLL直接生成，或者使用EXE+DLL名字生成
2. dll-hijack-with-callback.py: 类似detour hook，先执行代码再透传调用原始函数，老文件名字需要复制为 new_xxx.dll

### 缺陷

不支持C++
