# BypassUAC-Dll Version

利用COM组件绕过Windows UAC弹窗验证。为了方便利用白+黑绕过杀软，所以做成了Dll版本。在源码上做了一定程度的免杀处理。

## 用法

推荐使用可劫持的白名单程序来加载dll。在Releases中也提供了load.exe（仅使用Loadlibrary()和Freelibrary()来加载和释放dll）以供测试。

1. 启动不带参数的exe：

   `Load.exe "C:\Users\Administrator\Desktop\Program.exe"`

2. 启动带参数的exe：（以Rawcap.exe为例）

   `Load.exe "C:\Users\Administrator\Desktop\Rawcap.exe" "-s 20 192.168.1.1 C:\Users\Administrator\Desktop\1.pcap"`

**注意**：如果需要BypassUAC的exe启动参数中需要生成文件，那么文件必须以绝对路径表示，不然会生成到`c:\windows\system32`目录下。**可参考例2**

## 源码编译

项目中使用[Detours](https://github.com/microsoft/Detours)库来**hook Freelibrary() **函数。所以需先下载好[Detours](https://github.com/microsoft/Detours)，并将编译好的Detours库文件和头文件在Visual Studio中指定。

如果修改了`header.h`中的`#define SKey "..."`字段（此字段是RC4的密钥），那还需修改`#define Part1 "..."`字段中Part1的值。修改方法参考代码中的注释。