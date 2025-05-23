#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
NoIP DDNS 自动更新客户端
创建日期: 2024-01-22
"""

import base64
import logging
import os
import sys
import time
from typing import Optional, Tuple, List, Union

import numpy as np
import requests
from requests.exceptions import ConnectionError, Timeout, RequestException

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('noip_ddns_updater.log')
    ]
)
logger = logging.getLogger('noip_ddns_updater')

# 配置信息
CONFIG = {
    'username': 'your Enail',  # NoIP 账户邮箱
    'password': 'your password',  # NoIP 账户密码
    'hostname': 'your noip.com domain',  # DDNS 主机名
    'time_interval': 30,  # 检查时间间隔(分钟)
    'user_agent': 'no-ip shell script/1.0 mail@mail.com',  # 用户代理
    'connection_timeout': 10,  # 连接超时时间(秒)
    'retry_interval': 10,  # 重试间隔(分钟)
    'max_retries': 3  # 最大重试次数
}

# API 和探针地址
API_ENDPOINTS = {
    'noip_update': 'https://dynupdate.no-ip.com/nic/update',
    'ipv4_probes': [
        'https://ipv4.icanhazip.com/',
        'https://4.ipw.cn/'
    ],
    'ipv6_probes': [
        'https://ipv6.icanhazip.com/',
        'https://6.ipw.cn/'
    ]
}

# 错误状态码
ERROR_STATUSES = ['nohost', 'badauth', 'badagent', '!donator', 'abuse', '911']


def get_ip_address() -> str:
    """
    获取当前的 IP 地址（IPv4 和/或 IPv6）
    
    返回:
        str:  IP 地址字符串
    """
    ip_v4 = ip_v6 = None
    np.random.seed(int(time.time()) % 10000)  # 使用当前时间作为随机种子
    ipv4_probe = API_ENDPOINTS['ipv4_probes'][np.random.randint(0, len(API_ENDPOINTS['ipv4_probes']))]
    ipv6_probe = API_ENDPOINTS['ipv6_probes'][np.random.randint(0, len(API_ENDPOINTS['ipv6_probes']))]
    
    # 获取 IPv4 地址
    try:
        response = requests.get(ipv4_probe, timeout=CONFIG['connection_timeout'])
        if response.status_code == 200:
            ip_v4 = response.text.strip()
            logger.debug(f"获取到 IPv4 地址: {ip_v4}")
    except ConnectionError:
        logger.warning("IPv4 连接失败")
    except Timeout:
        logger.warning("IPv4 请求超时")
    except RequestException as e:
        logger.error(f"IPv4 请求异常: {e}")
    
    # 获取 IPv6 地址
    try:
        response = requests.get(ipv6_probe, timeout=CONFIG['connection_timeout'])
        if response.status_code == 200:
            ip_v6 = response.text.strip()
            logger.debug(f"获取到 IPv6 地址: {ip_v6}")
    except ConnectionError:
        logger.warning("IPv6 连接失败")
    except Timeout:
        logger.warning("IPv6 请求超时")
    except RequestException as e:
        logger.error(f"IPv6 请求异常: {e}")
    
    # 组合 IP 地址
    ip_addresses = list(filter(None, [ip_v4, ip_v6]))
    if not ip_addresses:
        logger.error("无法获取任何 IP 地址")
        return ""
    
    return ",".join(ip_addresses)


def update_ip_address(ip_address: str, retry_count: int = 0) -> bool:
    """
    更新 NoIP DDNS 的 IP 地址
    
    参数:
        ip_address (str): 要更新的 IP 地址
        retry_count (int): 当前重试次数
        
    返回:
        bool: 更新是否成功
    """
    if retry_count >= CONFIG['max_retries']:
        logger.error(f"达到最大重试次数 {CONFIG['max_retries']}，放弃更新")
        return False
    
    if not ip_address:
        logger.error("IP 地址为空，无法更新")
        return False
    
    # 准备认证信息
    auth_string = f"{CONFIG['username']}:{CONFIG['password']}"
    base64_auth = base64.b64encode(auth_string.encode()).decode()
    
    headers = {
        'Authorization': f"Basic {base64_auth}",
        'User-Agent': CONFIG['user_agent']
    }
    
    # 构建请求
    update_url = f"{API_ENDPOINTS['noip_update']}?hostname={CONFIG['hostname']}&myip={ip_address}"
    
    try:
        logger.info(f"正在更新 DDNS 记录为: {ip_address}")
        response = requests.get(update_url, headers=headers, timeout=CONFIG['connection_timeout'])
        result = response.text.strip()
        
        # 处理响应
        if result in ERROR_STATUSES:
            if result == '911':
                logger.warning("NoIP 服务器暂时不可用 (911)，30 分钟后重试")
                time.sleep(30 * 60)  # 30 分钟
                return update_ip_address(ip_address, retry_count + 1)
            else:
                logger.error(f"更新失败: {result}")
                return False
        else:
            logger.info(f"更新成功: {result}")
            return True
            
    except ConnectionError:
        logger.error("与 NoIP 服务器连接失败")
        time.sleep(CONFIG['retry_interval'] * 60)
        return update_ip_address(ip_address, retry_count + 1)
    except Timeout:
        logger.error("连接 NoIP 服务器超时")
        time.sleep(CONFIG['retry_interval'] * 60)
        return update_ip_address(ip_address, retry_count + 1)
    except Exception as e:
        logger.error(f"更新过程中发生未知异常: {e}")
        return False


def main():
    logger.info("NoIP DDNS 更新客户端已启动")
    current_ip = ""
    
    try:
        while True:
            try:
                new_ip = get_ip_address()
                if not new_ip:
                    logger.warning("无法获取 IP 地址，将在下次检查时重试")
                    time.sleep(CONFIG['time_interval'] * 60)
                    continue
                    
                if current_ip != new_ip:
                    logger.info(f"检测到 IP 变化: {current_ip} -> {new_ip}")
                    current_ip = new_ip
                    result = update_ip_address(new_ip)
                    
                    if not result:
                        logger.error("更新失败，程序将退出")
                        break
                else:
                    logger.info("IP 地址未发生变化，无需更新")
                    
                logger.info(f"等待 {CONFIG['time_interval']} 分钟后再次检查")
                time.sleep(CONFIG['time_interval'] * 60)
                
            except KeyboardInterrupt:
                logger.info("接收到中断信号，程序将退出")
                break
            except Exception as e:
                logger.error(f"发生未处理的异常: {e}")
                time.sleep(CONFIG['retry_interval'] * 60)
    except KeyboardInterrupt:
        logger.info("程序被用户中断")
    finally:
        logger.info("NoIP DDNS 更新客户端已停止")


if __name__ == '__main__':
    main()
