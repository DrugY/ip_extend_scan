import os
from IPy import IP
import subprocess
import time


class IPError(Exception):
    pass


class PortError(Exception):
    pass


class MainFileError(Exception):
    pass


# 调用masscan文件
# 主要方法为构建命令行字符串

class Masscan:
    __speed = 100

    def __init__(self, runDir):
        # 检查是否有root权限
        if os.geteuid() != 0:
            print("Masscan must be run as root!Aborting.")
            exit(-1)
        # 检查执行文件是否存在
        if not os.path.exists(runDir):
            raise MainFileError("文件不存在")
        # 初始化字段
        self.runDir = runDir
        self.__cmd = runDir
        self.__ipcmd = ""
        self.__portcmd = "-p "
        self.ipPool = []
        self.portPool = []
        self.outputType = ""
        self.outputDir = ""
    # 检查添加IP的合法性

    def __check_ip(self, value):
        try:
            if value.find("/") != -1:
                IP(value)
            elif value.find("-") != -1:
                ips = value.split("-")
                assert len(ips) == 2
                ip = []
                for ap in ips:
                    sep = ap.split(".")
                    assert len(sep) == 4
                    for index, i in enumerate(sep):
                        num = int(i)
                        assert num >= 0 and num <= 255
                        if index == 0:
                            assert num != 0
                    ip = ip + sep
                assert ip[0] <= ip[4]
                if ip[0] == ip[4]:
                    assert ip[1] <= ip[5]
                    if ip[1] == ip[5]:
                        assert ip[2] <= ip[6]
                        if ip[2] == ip[6]:
                            assert ip[3] <= ip[7]
            else:
                sep = value.split(".")
                assert len(sep) == 4
                for index, i in enumerate(sep):
                    num = int(i)
                    assert num >= 0 and num <= 255
                    if index == 0:
                        assert num != 0
                    elif index == 3:
                        assert num != 0
        except:
            raise IPError("IP(段)格式错误")
    # 检查添加端口的合法性

    def __check_ports(self, port):
        try:
            if type(port) == int:
                assert port >= 1 and port <= 65535
            elif port.find("-") != -1:
                k = port.find("-")
                start = int(port[:k])
                end = int(port[k + 1:])
                assert start <= end
                assert start >= 0
                assert end <= 65535
            else:
                num = int(port)
                assert num >= 0 and num <= 65535
        except:
            raise PortError("端口(段)格式错误")
    # 添加IP

    def addIP(self, strip: str):
        self.__check_ip(strip)
        self.ipPool.append(strip)
        if len(self.ipPool) == 1:
            self.__ipcmd += strip
        else:
            self.__ipcmd += "," + strip
    # 删除IP

    def delIP(self, strip: str):
        self.__check_ip(strip)
        self.ipPool.remove(strip)
        while strip in self.ipPool:
            self.ipPool.remove(strip)
        self.__ipcmd = ""
        for i in self.ipPool:
            self.__ipcmd += "," + i
        self.__ipcmd = self.__ipcmd[1:]
    # 添加端口（段）

    def addPorts(self, strports: str):
        self.__check_ports(strports)
        self.portPool.append(str(strports))
        if len(self.portPool) == 1:
            self.__portcmd += str(strports)
        else:
            self.__portcmd += "," + str(strports)
    # 删除端口（段）

    def delPorts(self, strports: str):
        self.__check_ports(strports)
        self.portPool.remove(strports)
        for strip in self.ipPool:
            self.ipPool.remove(strip)
        self.__portcmd = ""
        for i in self.portPool:
            self.__portcmd += "," + i
        self.__portcmd = "-p " + self.__portcmd[1:]
    # 设置扫描速度

    def setSpeed(self, speed: int):
        if type(speed) != int:
            raise ValueError("参数speed必须为int类型，然而传入了" + str(type(speed)))
        if speed <= 0:
            raise ValueError("速度必须大于0")
        Masscan.__speed = speed
    # 简单扫描（用于测试)

    def simpleScan(self, ip: str, port: str, speed=100):
        self.__check_ip(ip)
        self.__check_ports(port)
        excstr = self.runDir + " -p " + port + \
            " --rate " + str(speed) + " " + ip
        pcs = subprocess.Popen(excstr, shell=True)
        pcs.wait()
    # 设置结果输出方式及目录

    def setOutput(self, outputType, dir=""):
        try:
            assert outputType == "xml" or outputType == "json" or outputType == "list" or outputType == "grepable"
        except:
            raise ValueError("输出方式必须为 xml,json,list,grepable 中的一种")
        self.outputType = outputType
        self.outputDir = dir
    # 开始扫描，扫描进度会输出到stderr==None?控制台:stderr

    def Scan(self, stdout=None, stderr=None):
        if not self.ipPool or not self.portPool:
            raise ValueError("IP或端口池不能为空！")
        self.__cmd += " " + self.__portcmd + " " + \
            self.__ipcmd + " --rate " + str(self.__speed)
        if self.outputType != "":
            if self.outputDir == "":
                self.outputDir = "masscan_" + \
                    time.strftime("%m%d_%H%M", time.localtime())
            if self.outputType == "xml":
                self.__cmd += " -oX " + self.outputDir
            elif self.outputType == "json":
                self.__cmd += " -oJ " + self.outputDir
            elif self.outputType == "grepable":
                self.__cmd += " -oG " + self.outputDir
            elif self.outputType == "list":
                self.__cmd += " -oL " + self.outputDir
        # 子进程
        print(self.__cmd)
        pcs = subprocess.Popen(self.__cmd, shell=True,
                               stderr=stderr)
        return pcs
