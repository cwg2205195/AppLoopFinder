����ؼ����붨λ�������ߡ�

ʹ�÷�����
1.�Ȳɼ����ݣ�
1.1 ���ɼ�������ģ��
pin -t MyPinTool_MainModule.dll -filter_no_shared_libs -- app.exe
pin -pid 123 -t MyPinTool_MainModule.dll -filter_no_shared_libs

1.2 �ɼ���������ģ������
pin -t MyPinTool_AllInstruction.dll -- app.exe
pin -pid 123 -t MyPinTool_AllInstruction.dll

��������󣬻�����  pintool.log �ļ������м�¼��ģ����Ϣ�� EIP ��Ϣ��

2.���ݷ�����
python funCallAna.py pintool.log

�����ض����ܴ����Ĵ��������� ���������ɵ���ͼ�Ρ� �������޸� �������õĸ��� ��

3.IDA �������ɵ� IDA python �ű���Ѱ������ַ���
IDA ֱ���������ɵ� �ű����ɡ�
