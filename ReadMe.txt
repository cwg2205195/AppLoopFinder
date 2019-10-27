程序关键代码定位辅助工具。

使用方法：
1.先采集数据：
1.1 仅采集程序主模块
pin -t MyPinTool_MainModule.dll -filter_no_shared_libs -- app.exe
pin -pid 123 -t MyPinTool_MainModule.dll -filter_no_shared_libs

1.2 采集程序所有模块数据
pin -t MyPinTool_AllInstruction.dll -- app.exe
pin -pid 123 -t MyPinTool_AllInstruction.dll

程序结束后，会生成  pintool.log 文件，其中记录了模块信息和 EIP 信息。

2.数据分析：
python funCallAna.py pintool.log

根据特定功能触发的次数，输入 次数，生成调用图形。 （可以修改 函数调用的个数 ）

3.IDA 载入生成的 IDA python 脚本，寻找相关字符串
IDA 直接载入生成的 脚本即可。
