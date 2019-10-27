# -*- coding: UTF-8 -*-
import matplotlib.pyplot as plt
import json
import sys
import time 


moduleBlacklist=["APPHELP.DLL","MFC42.DLL","NTDLL.DLL","KERNELBASE.DLL","KERNEL32.DLL","MSVCRT.DLL","BCRYPTPRIMITIVES.DLL","CRYPTBASE.DLL","SSPICLI.DLL","RPCRT4.DLL","SECHOST.DLL","ADVAPI32.DLL","UCRTBASE.DLL","COMBASE.DLL","MSVCP_WIN.DLL","USER32.DLL","IMM32.DLL","GDI32FULL.DLL","WIN32U.DLL","GDI32.DLL","COMCTL32.DLL","SHCORE.DLL","SHLWAPI.DLL","CFGMGR32.DLL","PROFAPI.DLL","UMPDC.DLL","POWRPROF.DLL","KERNEL.APPCORE.DLL","WINDOWS.STORAGE.DLL","CRYPTSP.DLL","SHELL32.DLL","COMDLG32.DLL","OLE32.DLL","WINMMBASE.DLL","WINMM.DLL","OLEAUT32.DLL","PROPSYS.DLL","IPHLPAPI.DLL","BCRYPT.DLL","WINSPOOL.DRV","WS2_32.DLL","UXTHEME.DLL","MSCTF.DLL","COREMESSAGING.DLL","SECUR32.DLL","NTMARTA.DLL","WINTYPES.DLL","COREUICOMPONENTS.DLL","TEXTINPUTFRAMEWORK.DLL","IERTUTIL.DLL","CLBCATQ.DLL","QQPINYINTSF.DLL","WTSAPI32.DLL","WININET.DLL","VERSION.DLL","PSAPI.DLL","MSIMG32.DLL","NSI.DLL","DNSAPI.DLL","QQPINYIN.IME","RSAENH.DLL","MSWSOCK.DLL","ONECOREUAPCOMMONPROXYSTUB.DLL","ONECORECOMMONPROXYSTUB.DLL","APPRESOLVER.DLL","USERENV.DLL","SLC.DLL","SPPC.DLL","BCP47LANGS.DLL","CLDAPI.DLL","FLTLIB.DLL","URLMON.DLL","WINDOWS.STATEREPOSITORYPS.DLL","EDPUTIL.DLL"]# 2019年10月23日 20:41:45 模块黑名单，在黑名单内的模块数据不做分析，比如系统模块： kernel32、kernelbase、user32 等

modules = {}			# --------> 保存所有模块的信息
threads = {}			# --------> 保存所有线程的所有模块的函数调用信息
instCount = 0 			# 执行函数调用的指令数
curModuleName = ""		# --------> 2019年10月23日 20:44:25  当前正在分析的模块名 ,希望能够输出函数调用的 EIP的 RVA 信息，因为直线图无法精确定位这个数值。
curThreadId = 0			# --------> 2019年10月26日 12:13:07 当前分析的数据所属的线程ID
AnalysisModulesInfo = {}# --------> 2019年10月26日 12:17:55 按照模块名作为字典的分析结果，用于生成 IDA 脚本，把所有相关函数引用的字符串输出到文件

# 展示 线程 X 的 模块 M 的EIP变化图 
def AnaNums(nums,tid,moduleName):
	print("drawing %d call site\n" % len(nums))
	plt.plot(nums,linewidth=1)
	plt.title("Program run time function call for thread [" + tid + "] module: "+ moduleName, fontsize=14)
	plt.ylabel("EIP's RVA ", fontsize=14)
	plt.show()

class DataAnaEng:
	def __init__(self,data):
		self.data = data
		self.analysedResult = {}

	def hashArray(self,array):
		result = "".join([str(n) for n in array])
		return hash(result)
	
	#	输出 array 里所有 EIP 的 RVA。
	def dumpRVAs(self,array):
		global curModuleName
		global modules
		begin = modules[curModuleName]["begin"]
		ret = []
		for item in array:
			ret.append(item-begin)
		return ret
	
	# 根据传递的 length 作为长度，每 length 个数据作为一组，计算hash
	# 2019年10月22日 23:19:01 frequency 表示 想要寻找的循环发生的次数 
	def AnaByLength(self,length,frequency):
		end = len(self.data)
		offset = 0 
		while offset + length < end :				# ---------> 还要修改哦，这样是不准确的
			tmpArray = self.data[offset:offset+length]
			h = self.hashArray(tmpArray)
			try:
				self.analysedResult[h].append(offset)
				#self.analysedResult[h].append(tmpArray)
			except KeyError as err:
				self.analysedResult[h] = []
				self.analysedResult[h].append(offset)
				#self.analysedResult[h].append(tmpArray)
			#offset += length
			offset += 1 

		# 2019年10月22日 22:50:45 由于人工触发某个动作的次数是可以控制的，所以产生的循环也是人工可以控制的。
		# 2019年10月22日 22:51:16 所以呢， 就可以通过循环的个数进行过滤，可以试试！ 
		global AnalysisModulesInfo
		global curThreadId
		global curModuleName
		# 为模块列表创建模块信息
		try:
			AnalysisModulesInfo[curModuleName]
		except KeyError as e:
			AnalysisModulesInfo[curModuleName]={}
		# 为模块创建线程信息
		try:
			AnalysisModulesInfo[curModuleName][curThreadId]
		except KeyError as e:
			AnalysisModulesInfo[curModuleName][curThreadId]={}

		for key in self.analysedResult.keys():	# key 就是哈希值
			l = len(self.analysedResult[key])
			if l == frequency :
				offsetList = self.analysedResult[key]
				try:
					offset = self.analysedResult[key][0]
					AnalysisModulesInfo[curModuleName][curThreadId][key] = self.dumpRVAs(self.data[offset:offset+length])
				except Exception as e:
					print(e)
				for offset in offsetList:
					#print(self.dumpRVAs(self.data[offset:offset+length]))	#这里可以获取所有 RVA
					x = list(range(offset,offset+length))
					plt.plot(x,self.data[offset:offset+length])
				
				# 输出执行该模块的所有线程的所有RVA


		#global curModuleName
		plt.title("Current module : " + curModuleName,fontsize = 16)
		plt.ylabel("EIP's RVA ", fontsize=14)
		plt.show()

# 根据模块信息，直接生成 IDA python 脚本
def codeGenerator():
	src0 = '''# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
import time 

ImageBase = get_first_seg() - 0x1000         # ---> 当前分析的模块的基址

class timer:
    def __init__(self):
        self.startAt=0
    def start(self):
        self.startAt = time.time()
    
    def stop(self):
        stopAt = time.time()
        print("%d seconds elapsed \\n" % int(stopAt - self.startAt ))

def getStringRefs(addr):
    ret = {}
    start = GetFunctionAttr(addr,FUNCATTR_START)
    if start == BADADDR:
        return ret
    dism_addrs = list(idautils.FuncItems(start))        
    for addr in dism_addrs:
        for i in range(0,2):
            opndType = GetOpType(addr,i)               
            if opndType == o_imm :
                opnd = get_operand_value(addr,i)
                if get_str_type(opnd) == STRTYPE_C:
                    string=""
                    offset = 0 
                    while True:
                        val = get_wide_byte(opnd+offset) 
                        if val == 0:
                            break
                        offset += 1
                        string += chr(val)
                    if string != "":
                        ret[addr]=string
    return ret 

def filterVaList(VaList):
    ret = []
    for va in VaList:
        funcAddr = GetFunctionAttr(va,FUNCATTR_START)
        if funcAddr not in ret:
            ret.append(funcAddr)
    return ret

def work(data):
    count = 0
    t = timer()
    t.start()
    for tid in data.keys():
        VAList = []             
        for hash in data[tid]:
            rvaList = []
            try:
                rvaList = [rva+ImageBase for rva in data[tid][hash]]
            except Exception as e :
                print(e)
            VAList += rvaList
        
        print("[+]Current thread ID:  " + tid)
        VAList = filterVaList(VAList)
        count += len(VAList)
        for va in VAList:
            #print("va = %x \\n" % va)
            result = getStringRefs(va)
            if len(result) == 0:
                continue
            #print(result)
            for key in result.keys():
                print("%x -> %s" % (key,result[key]))
    t.stop()
    print("Total %d VA Analysed" % count)

'''
	global AnalysisModulesInfo
	for moduleName in AnalysisModulesInfo.keys():
		data = AnalysisModulesInfo[moduleName].__str__()
		src1 = "data="+ data +"\nwork(data)"
		outFile = moduleName + ".py"
		of = open(outFile,"w")
		of.write(src0)
		of.write(src1)
		of.close()
		print("Generated IDA python script : " + outFile)

# 提前退出
def earlyExit():
	f = open("ModulesInfo.json","w")
	f.write(AnalysisModulesInfo.__str__())
	f.close()
	codeGenerator()
	exit(0)

def test(fname):
	f=open(fname,"rb")
	f.seek(0x46)			#-> 去掉 pin 日志头
	dat = f.read()
	dat=dat[:-4] + b']}'
	jdat = json.loads(dat)
	f.close()
	startAt = time.time()
	dats = jdat["dat"]		# 获取所有信息
	global instCount
	global modules
	global threads
	global curModuleName
	for item in dats:
		type = item["type"]
		if type == "eipInfo":	# EIP -> 解析EIP所属的模块，加入到对应线程的对应模块信息中
			instCount +=1
			#为了减少函数调用，直接获取 EIP 所属模块名
			moduleName = ""
			eip = int(item["rva"],base=16)
			tid = item["tid"]
			for key in modules.keys():
				module = modules[key]
				#print(key)
				begin = module["begin"]
				end   = module["end"]
				if eip > begin and eip < end:
					moduleName = key
					break 
			if moduleName == "":
				print("eip " + item["rva"] + "is not in range !")
				continue
			
			try:
				threads[tid]
			except KeyError as err:
				#print(err)
				threads[tid]={}
			
			try:
				threads[tid][moduleName].append(eip)
			except KeyError as err:
				threads[tid][moduleName] = []
				threads[tid][moduleName].append(eip)
				
		elif type == "imgInfo":	# module -> 把模块信息导入到模块字典中
			modules[item["name"]] = {}
			module = modules[item["name"]]
			module["begin"] = int(item["begin"],base=16)
			module["end"] = int(item["end"],base=16)

	#print(modules)
	print("total %d functions called \ntotal %d threads\ntotal %d modules loaded\n" % (instCount,len(threads.keys()),len(modules.keys())) )
	#print(threads)
	finishAt = time.time()
	print("%d seconds for analyzing \n" % int(finishAt - startAt ))
	'''
	得到的结果事例：
	{
		0x1:{			//-> 线程ID
			"ntdll.dll":{			//-> 模块名
				0x1234:[1,6,99]				//-> 哈希 以及 计算出该哈希的EIP的起始索引
			}
		}
	}
	'''
	# 输出所有线程的所有模块的 EIP 变化图
	for key in threads.keys():
		global curThreadId
		curThreadId = key 
		thread = threads[key]
		#t = 0 
		for moduleName in thread.keys():
			curModuleName = moduleName 
			#print("\"" + curModuleName + "\",", end='')
			print("当前模块" + curModuleName)
			#continue
			if curModuleName.upper() in moduleBlacklist:	# 黑名单识别 2019年10月23日 21:04:20
				continue
			eng = DataAnaEng(thread[moduleName])
			print("当前线程ID :" + key)
			print("请输入循环发生的次数(输入exit退出)：")
			frequency = input()
			if frequency == "exit":
				earlyExit()
			try:
				frequency = int(frequency)
				eng.AnaByLength(25,frequency)			# ==================>>>>> 手动修改函数个数 <<<<<==================
				
			except Exception as e:
				print(e)
				print("请输入整数！")
			AnaNums(thread[moduleName],key,moduleName)
	global AnalysisModulesInfo
	#print(AnalysisModulesInfo)
	f = open("ModulesInfo.json","w")
	f.write(AnalysisModulesInfo.__str__())
	f.close()
	codeGenerator()


if __name__ == "__main__":
	fname = "jd.json"
	if len(sys.argv) == 1:
		pass 
	else:
		fname = sys.argv[1]
	print("Analysing %s \n" % fname)
	test(fname)
