#!/usr/bin/env python
#-*- encoding:utf-8 -*-

#########################################################################
# 数据通信加解密工具类
# @copyright   Copyright © 2019 枫芒科技
# @author      wangguanqun <wangguanqun@fmtech.me>
# @version     1.0.0
# @link        http://www.fmtech.me
#########################################################################

import base64
import string
import random
import hashlib
import time
import struct
from Crypto.Cipher import AES
import sys
import socket
import json

import ErrorCode
from JsonFormat import JsonFormat

"""
关于 Crypto.Cipher 模块，ImportError: No module named 'Crypto' 解决方案
请到官方网站 https://www.dlitz.net/software/pycrypto/ 下载、安装后使用；
或者使用 pip install pycrypto 命令安装
"""
class EncryptorLogic(object):
    
    # 构造方法
    # @param companyKey: 企业标识
    # @param token: 用于计算签名的 token
    # @param encodingAESKey: 经过 base64 编码的 AESKey

    def __init__(self, companyKey, token, encodingAESKey):
        
        self.companyKey = companyKey
        self.token = token
        self.aesKey = base64.b64decode(encodingAESKey + "=")
        
        # 设置加解密模式为AES的CBC模式   
        self.mode = AES.MODE_CBC

        # 块大小（字节）
        self.blockSize = 32

    # 加密需要发送的消息
    # @param msg: 待加密的明文消息
    # @param nonce: 随机串
    # @param timestamp: 时间戳
    # encrypted: 加密后用来发送的json格式字符串（包含加密字符串、签名、时间戳、随机数）
    # return：成功0，encrypted;失败返回对应的错误码, None

    def encrypt(self, msg, nonce = None, timestamp = None):
            
        # 明文字符串由16个字节的随机字符串、4个字节的 msg 长度、明文 msg 和 companyKey 拼接组成。
        # 其中 msg 长度为 msg 的字节数，网络字节序；companyKey 为企业标识；
        text = self.getRandomStr(16) + struct.pack("I", socket.htonl(len(msg))) + msg + self.companyKey
        
        # 将拼接的字符串采用 PKCS#7 填充，长度扩充至32字节的倍数
        text = self.pkcs7Pad(text)

        # 加密
        cryptor = AES.new(self.aesKey, self.mode, self.aesKey[:16])
        try:
            # 使用BASE64对加密后的字符串进行编码
            encrypted = base64.b64encode(cryptor.encrypt(text))            
        except Exception,e:
            print e
            return  ErrorCode.ERROR_ENCRYPT_AES,None

        if nonce is None:
            nonce = str(random.randint(10000000, 999999999))
           
        if timestamp is None:
            timestamp = str(int(time.time()))

        # 生成安全签名
        ret,signature = self.signature(self.token, timestamp, nonce, encrypted)
        if ret != 0:
            return ret,None
        jsonFormatObj = JsonFormat()
        return ret,jsonFormatObj.response(encrypted, signature, timestamp, nonce)

    # 解密收到的消息
    # @param content: 已加密的内容
    # @param msgSignature: 签名
    # @param nonce: 随机数
    # @param timestamp: 时间戳
    # return：成功0，解密后的原文，普通字符串或者json格式字符串;失败返回对应的错误码, None    

    def decrypt(self, content, msgSignature, nonce, timestamp):
        ret,signature = self.signature(self.token, timestamp, nonce, content)
        if ret != 0:
            return ret, None 
        if not signature == msgSignature:
            print "signature not match"
            print signature
            return ErrorCode.ERROR_INVALID_SIGNATURE, None

        try:
            cryptor = AES.new(self.aesKey, self.mode, self.aesKey[:16])

            # 使用BASE64对密文进行解码，然后AES-CBC解密
            decrypted  = cryptor.decrypt(base64.b64decode(content))
        except Exception,e:
            print e 
            return ErrorCode.ERROR_DECRYPT_AES,None

        try:
            # 去掉补位字符串
            result = self.pkcs7Unpad(decrypted)

            # 去除16位随机字符串
            content = result[16:]
            msgLen = socket.ntohl(struct.unpack("I",content[ : 4])[0])
            msg = content[4 : msgLen+4] 
            fromCompanyKey = content[msgLen+4:]
        except Exception,e:
            print e
            return  ErrorCode.ERROR_ILLEGAL_BUFFER,None
        if  fromCompanyKey != self.companyKey:
            print "companyKey not match"
            print fromCompanyKey 
            return ErrorCode.ERROR_INVALID_COMPANY_KEY,None
        return ErrorCode.SUCCESS_OK,msg

    # 返回指定长度的随机字符串，只包含大小字母和数字
    # @param len 需要返回的字符串长度
    # @return：指定长度随机字符串

    def getRandomStr(self, len):
        rule = string.letters + string.digits
        str = random.sample(rule, len)
        return "".join(str)

    # 用SHA1算法生成安全签名
    # @param token 签名密钥
    # @param timestamp 时间戳
    # @param nonce 随机数
    # @param content base64编码的密文
    # @return：安全签名

    def signature(self, token, timestamp, nonce, content):
        try:
            sortArray = [token, timestamp, nonce, content]
            sortArray.sort()
            sha = hashlib.sha1()
            sha.update("".join(sortArray))
            return ErrorCode.SUCCESS_OK, sha.hexdigest()
        except Exception,e:
            print e
            return ErrorCode.ERROR_COMPUTER_SIGNATURE, None

    # 将字符串使用 PKCS#7 pad 方法填充，使长度至32字节的倍数
    # @param text 待填充的原始内容
    # @return：填充后的内容

    def pkcs7Pad(self, text):
        # 计算需要填充的位数
        padding = self.blockSize - (len(text) % self.blockSize)
        if padding == 0:
            padding = self.blockSize

        # 获得补位所用的字符
        pattern = chr(padding)
        return text + pattern * padding
    
    # 使用 PKCS#7 unpad 方法将多余的字符去掉
    # @param text 待截取的已被填充的内容
    # @return：截取后的内容

    def pkcs7Unpad(self, text):
        pad = ord(text[-1])
        if pad<1 or pad >32:
            pad = 0
        return text[:-pad]