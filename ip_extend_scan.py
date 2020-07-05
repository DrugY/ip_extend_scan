import re
from autumn import executor
import os
import subprocess
import aiohttp
import json
import time
from pmasscan import Masscan
import traceback

service = executor.Executor()


def do_scan(ips, ports, speed):
    try:
        # 临时输出文件
        output = "temp.txt"
        # masscn的路径  需要配置
        task = Masscan("bin/masscan")
        # masscan扫描配置
        for aip in ips:
            print(aip)
            task.addIP(aip)
        for aport in ports:
            task.addPorts(str(aport))
        task.setSpeed(speed)

        time_num = time.strftime("%Y%m%d%H%M%S", time.localtime())

        print("设置结果输出文件")
        # 设置结果输出文件
        task.setOutput("list", time_num + ".result")

        f = open(output, "w")
    except Exception as e:
        print("Error in the scan preparation stage:" + str(e))
        return {}, "Error in the scan preparation stage:" + str(e)
    try:
        print("调用扫描模块")
        # 调用扫描模块
        pcs = task.Scan(stderr=f)
        time.sleep(18)
        print("循环读取文件获取状态")
        # 循环读取文件获取状态
        old_percent = -1
        while True:
            # print("提取进度信息")
            # 提取进度信息
            outf = open(output, "rb+")
            lines = outf.read().decode().replace("\r", "").replace(" ", "")
            k1 = lines.rfind("-kpps")
            if k1 == -1:
                percent = 0
            else:
                percent = int(float(lines[k1 + 6:k1 + 10]))

            # print("更新任务状态")
            # 更新任务状态
            if old_percent != percent:
                # print("Process:" + str(percent) + "%")
                old_percent = percent
                if percent == 100:
                    time.sleep(20)
                    break
            outf.close()
            print("休眠一段时间")
            # 休眠一段时间
            time.sleep(2)
        f.close()
    except Exception as err:
        print("Error in scanning:", exc_info=True)
        return {}, "Error in scanning:" + str(err)
    try:
        data = {}
        print("从结果文件中提取数据")
        rf = open(time_num + ".result")
        for line in rf.readlines():
            line = line[:-1]
            if len(line) == 0 or line[0] == "#":
                continue
            info = line.split(" ")
            if len(info) < 4:
                continue
            if info[0] == "open":
                if info[3] not in data.keys():
                    data[info[3]] = []
                data[info[3]].append(int(info[2]))
        rf.close()
        print("删除结果文件:" + time_num + ".result")
        os.remove(time_num + ".result")
        # 删除结果文件
        print("扫描结果", data)
        return data, ""
    except Exception as err:
        traceback.prine_exc()
        return data, "Error when extracting results:" + str(err)


def ipv4_filter(item):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(item):
        if '/' not in item:
            item = "%s.0/24" % '.'.join(item.split(".")[:3])
        return item
    else:
        return False


# 定义执行器所能接收的数据类型,data为list
# ip列表
'''
["12.24.21.45","12.24.15.24"...]
'''


@service.preprocess("ip", timeout=2)
def preprocess_for_ip(data, config):
    return data


# 处理ip集合的函数
'''
输入为["12.24.21.45","12.24.15.24"...]
输出为[
    {
        "ip":,
        "port_info":{}
    },{}...
]
'''


@service.handle_all_inputs(timeout=50)
def handle_ips(inputs, config):
    default_ports = [21, 22, 23, 25, 80, 110, 111, 135, 139, 443, 445, 1080, 5900, 3389, 8000, 8080, 3306, 1433, 1521,
                     5432, 6379, 27017]
    ports = config.get("port", default_ports)
    speed = config.get("speed", 2000)
    ips = []
    for item in inputs:
        temp = ipv4_filter(item)
        if temp:
            ips.append(temp)
    print("The real input:")
    print(ips)

    # 构造输出的格式
    temp_return = []
    for item in ips:
        temp_one = {}
        temp_one["ip"] = item
        temp_one["port_info"] = {}
        temp_return.append(temp_one)

    data, error_info = do_scan(ips, ports, speed)
    print("data:")
    print(data)
    for ip in data:
        for i in range(0, len(ips)):
            if ip[:ip.rfind(".")] == ips[i][:ips[i].rfind(".")]:
                # data[ip]扫描结果不为空 而且之前没有ip的扫描记录
                if ip not in temp_return[i]["port_info"] and len(data[ip]):
                    temp_return[i]["port_info"][ip] = data[ip]
                else:
                    temp_return[i]["port_info"][ip] = temp_return[i]["port_info"][ip] + data[ip]
    if error_info:
        print("Something wrong while gaining ip scan result")
    final_return = []
    for item in temp_return:
        # 除去port_info为空的ip端口信息
        if item["port_info"]:
            final_return.append(item)
    print("Final return for scan:")
    print(final_return)
    return final_return


# @sv.handle_input_items(time_out=50)
# def ips_scan(input_items, config):
#     default_ports = [80, 67, 68, 110, 25, 20, 21, 69, 53, 137,
#                          138, 139, 119, 161, 135, 8000, 4000, 23, 443, 1080, 1024]
#     ports = config.get("port", default_ports)
#     ips=[]

#     input_items = list(map(ipv4_filter, input_items))
#     sv.logger.debug("#####")
#     sv.logger.debug(input_items)
#     for item in input_items:
#         if item["error_info"] is None:
#             ips.append(item["input"])
#     speed = config.get("speed", 2000)
#     data, error_info = do_scan(ips, ports, speed)
#     sv.logger.debug("data:")
#     sv.logger.debug(data)
#     for ip in data:
#         for item in input_items:
#             if ip[:ip.rfind(".")] == item["input"][:item["input"].rfind(".")]:
#                 if item["output"] is None:
#                     item["output"]=[]
#                     item["output"].append(dict())
#                 else:
#                     if ip not in item["output"][0]:
#                         item["output"][0][ip]=data[ip]
#                     else:
#                         item["output"][0][ip]=item["output"][0][ip]+data[ip]
#     if error_info:
#         for item in input_items:
#             item["error_info"] = error_info
#     sv.logger.debug("========return========")
#     sv.logger.debug(input_items)
#     return input_items

# 后处理，获取开放了443端口的ip列表
@service.afterprocess("ip", timeout=2)
def afterprocess_to_ip1(data, config):
    '''
    输入为[
        {
            "ip":,
            "port_info":{"124.2.1,6":[12,45],"124.2.1.5":[12,212]}
        },{}...
    ]
    输出为
    ["10.24.24.12","12.21.21.21"...]开放了443端口的ip列表
    '''
    final_return = []
    for item in data:
        temp_data = item["port_info"]
        for port_info in temp_data:
            if 443 in temp_data[port_info]:
                final_return.append(port_info)

    print("The ips of open 443 port")
    print(final_return)
    return final_return


# 后处理，存入数据库中的信息
@service.afterprocess("ip-scan", timeout=2)
def afterprocess_to_ip2(data, config):
    '''
    输入为[
        {
            "ip":,
            "port_info":{"124.2.1,6":[12,45],"124.2.1.5":[12,212]}
        },{}...
    ]
    输出为[{
            "ip":,
            "ports":[]
        },{}...
    ]  ip和它开放的端口信息
    '''
    final_return = []
    for item in data:
        temp_data = item["port_info"]
        for port_info in temp_data:
            # 去掉可能空的列表
            if len(temp_data[port_info]):
                single_return = {}
                single_return["ip"] = item
                single_return["new_ip"] = port_info
                single_return["ports"] = temp_data[port_info]
                final_return.append(single_return)
    print("The result for db from ip scan")
    print(final_return)
    return final_return


# run service
service.reset_cmd()

# @sv.to_next(name="443_ips")
# def to_next1(deal_data):
#     '''
#     deal_data={
#         "input":"124.2.1.2"
#         "output":[{"124.2.1,6":[12,45],"124.2.1.5":[12,212]}]
#     }
#     '''
#     temp_data = deal_data["output"][0]
#     sv.logger.error(
#         "======================== 443_IPS ==========================")

#     final_return=[]
#     for item in temp_data:
#         if 443 in temp_data[item]:
#             final_return.append(item)

#     sv.logger.debug(final_return)
#     return final_return


# @sv.to_next(name="ip-scan")
# def to_next2(deal_data):
#     '''
#     deal_data={
#         "input":"124.2.1.2"
#         "output":[{"124.2.1.5":[12,122],"124.2.1.6":[45,52,12]}]
#     }
#     '''
#     sv.logger.error(
#         "======================== ip_SCAN ==========================")
#     try:
#         final_return=[]
#         temp_data=deal_data["output"][0]
#         for item in temp_data:
#             single_data = {}
#             single_data["ip"] = item
#             single_data["ports"] = temp_data[item]
#             final_return.append(single_data)
#         sv.logger.debug(final_return)
#         return final_return
#     except Exception as error:
#         temp_error = "Errors occured while handling ip-port:"+str(error)
#         sv.logger.error(temp_error)
#         return []


# sv.run()
