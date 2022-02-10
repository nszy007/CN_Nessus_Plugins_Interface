#coding="utf-8"

import sys
import requests
import json
import csv

#查询接口地址:
server = "http://127.0.0.1:8081/autoinfo/"


def norepeat(alist):
    blist = []
    for i in alist:
        if i not in blist:
            blist.append(i)
    return blist
def getplugininfo(id):  #通过数据接口获取当前插件id中文数据
    url = "{server}{pluginid}".format(server=server,pluginid=id)
    try:   
        response = requests.get(url,timeout=30)
        if response.status_code == 200:
            result = json.loads(response.text)
        else:
            result = {}
    except:
        result = {}
    return result

def translate(pluginlist): 
    for plugin in pluginlist:
        print("正在获取插件ID为" + plugin[0] + " 主机地址为" + plugin[1] + " 服务端口为" + plugin[3] + "的中文信息")
        res = getplugininfo(plugin[0])
        plugin[4] = res['PluginName']
        plugin[5] = res['Synopsis']
        plugin[6] = res['Risk']
        plugin[7] = res['Description']
        plugin[8] = res['Solution']

    return pluginlist

def go(files):
    Critical = []
    High = []
    Medium = []
    for file in files:
        with open(file,'r') as f:
            reader = csv.DictReader(f)
            for i in reader:
                if i['Risk'] == 'Critical':
                    Critical.append([i['Plugin ID'], i['Host'], i['Protocol'], i['Port'], i['Name'], i['Synopsis'], i['Risk'], i['Description'], i['Solution']])
                elif i['Risk'] == 'High':
                    High.append([i['Plugin ID'], i['Host'], i['Protocol'], i['Port'], i['Name'], i['Synopsis'], i['Risk'],  i['Description'], i['Solution']])
                elif i['Risk'] == 'Medium':
                    Medium.append([i['Plugin ID'], i['Host'], i['Protocol'], i['Port'], i['Name'], i['Synopsis'], i['Risk'],  i['Description'], i['Solution']]) 

    Critical = norepeat(Critical)
    High = norepeat(High)
    Medium = norepeat(Medium)
    Critical = translate(Critical)
    High = translate(High)
    Medium = translate(Medium)
    print("正在生成新的中文统计文件")
    header = ['插件ID','主机地址','协议类型','服务端口', '漏洞名称', '漏洞简介', '威胁等级', '漏洞描述','整改建议']
    with open("newcncsv.csv" ,"w" , encoding="gb18030",newline='') as w:
        writer = csv.writer(w)
        writer.writerow(header)
        writer.writerows(Critical)
        writer.writerows(High)
        writer.writerows(Medium)
    print("运行完成")
    return


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("eg:python cncsv.py 1.csv 2.csv ...")
    else:
        filepath =sys.argv[1:]
        go(filepath)