#!/usr/bin/env python
#-*- encoding:utf-8 -*-

#########################################################################
# 格式化Json数据
# @copyright   Copyright © 2019 枫芒科技
# @author      wangguanqun <wangguanqun@fmtech.me>
# @version     1.0.0
# @link        http://www.fmtech.me
#########################################################################

import json

class JsonFormat:
    
    # 生成通用回复消息的json格式
    # @param encrypt 加密内容
    # @param msgSignature 签名
    # @param timestamp 时间戳
    # @param nonce 随机数
    # @return：json格式字符串

    def response(self, encrypt, msgSignature, timestamp, nonce):
        respData = {
                    'encrypt' : encrypt,
                    'msgSignature': msgSignature,
                    'timestamp'    : timestamp,
                    'nonce'        : nonce
                    }
        
        return json.dumps(respData, indent=2)
 