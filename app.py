#!/usr/bin/env python3
from flask import Flask, Response
import prometheus_client as prom
import requests
import hashlib
import os
import logging
import warnings
import json
# 关闭警告
requests.packages.urllib3.disable_warnings()
warnings.filterwarnings("ignore")

# 日志
logging.basicConfig(level = logging.INFO,format = '%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('schedule').propagate = False
logger = logging.getLogger(__name__)

IK_USERNAME  = os.getenv("IK_USERNAME")
IK_PASSWORD  = os.getenv("IK_PASSWORD")
IK_IPADDR    = os.getenv("IK_IPADDR")
IK_MGR_PORT  = os.getenv("IK_MGR_PORT")
IK_USE_HTTPS = os.getenv("IK_USE_HTTPS")

IK_URL = f"{IK_IPADDR}:{IK_MGR_PORT}" if IK_MGR_PORT else IK_IPADDR
IK_URL = f"https://{IK_URL}" if IK_USE_HTTPS else f"http://{IK_URL}"

if not IK_USERNAME: logger.error("Need Env IK_USERNAME");exit()
if not IK_PASSWORD: logger.error("Need Env IK_PASSWORD");exit()
if not IK_IPADDR:   logger.error("Need Env IK_IPADDR");exit()
session = requests.Session()
if IK_USE_HTTPS: session.verify=False

def req_ikuai(uri, data={}):
    h = {
        "Content-Type": "application/json;charset=UTF-8",
        "User-Agent" : "Prometheus exporter",
    }
    url = f"{IK_URL}{uri}"
    try:
        if data != {}:
            ret = session.post(url, json=data, headers=h).json()
        else:
            ret = session.get(url, headers=h).json()
        return ret
    except Exception as e:
        logger.error(f"Request Error, uri = {uri} | data = {json.dumps(data)}")
        logger.error(e)
        return {"Data": False, "Result": False, "ErrMsg": e}
    

def ikuai_call(data):
    uri = "/Action/call"
    return req_ikuai(uri, data)["Data"]

def login_ikuai():
    d = {
        "username" : IK_USERNAME,
        "passwd" : hashlib.md5(IK_PASSWORD.encode()).hexdigest()
    }
    logger.info(f"Login iKuai {IK_URL}")
    res = req_ikuai("/Action/login", d)
    if not res: return False
    if res["Result"] == 10000:
        logger.info("Login Success")
        return True
    logger.error(f"Login Error, {res['ErrMsg']}")
    return False

login_ikuai()

def get_ikuai_version(registry):
    data = {"func_name":"upgrade","action":"show","param":{"TYPE":"data"}}
    res = ikuai_call(data)
    if not res: return registry
    res = res["data"]
    prom.Gauge('ikuai_version_libproto', '协议库版本', ["now", "new"], registry=registry).labels(res["libproto_ver"], res["new_libproto_ver"]).inc(0)
    prom.Gauge('ikuai_version_libaudit', '通讯工具特征库版本', ["now", "new"], registry=registry).labels(res["libaudit_ver"], res["new_libaudit_ver"]).inc(0)
    prom.Gauge('ikuai_version_libdomain', '网址库版本', ["now", "new"], registry=registry).labels(res["libdomain_ver"], res["new_libdomain_ver"]).inc(0)
    data = {"func_name":"sysstat","action":"show","param":{"TYPE":"verinfo"}}
    res2 = ikuai_call(data)["verinfo"]
    prom.Gauge('ikuai_version_system_str', '路由系统版本', ["now", "new", "now_str"], registry=registry).labels(res["system_ver"], res["new_system_ver"], res2["verstring"]).inc(0)
    return registry

def get_iface_stream(registry):
    data = {"func_name":"monitor_iface","action":"show","param":{"TYPE":"iface_stream"}}
    res = ikuai_call(data)
    if not res: return registry
    res = res["iface_stream"]
    upload      = prom.Gauge('ikuai_iface_stream_upload', '接口实时上传', ["ip_addr", "interface", "comment"], registry=registry)
    download    = prom.Gauge('ikuai_iface_stream_download', '接口实时下载', ["ip_addr", "interface", "comment"], registry=registry)
    connect_num = prom.Gauge('ikuai_iface_stream_connect_num', '接口实时下载', ["ip_addr", "interface", "comment"], registry=registry)
    total_up    = prom.Gauge('ikuai_iface_stream_total_upload', '接口总计上传', ["ip_addr", "interface", "comment"], registry=registry)
    total_down  = prom.Gauge('ikuai_iface_stream_total_download', '接口总计下载', ["ip_addr", "interface", "comment"], registry=registry)
    for r in res:
        upload.labels(r["ip_addr"], r["interface"], r["comment"]).set(r["upload"])
        download.labels(r["ip_addr"], r["interface"], r["comment"]).set(r["download"])
        total_up.labels(r["ip_addr"], r["interface"], r["comment"]).set(r["total_up"])
        total_down.labels(r["ip_addr"], r["interface"], r["comment"]).set(r["total_down"])
        if r["connect_num"] == "--": r["connect_num"] = 0
        connect_num.labels(r["ip_addr"], r["interface"], r["comment"]).set(r["connect_num"])
    return registry

def get_client_stream(registry):
    data = {"func_name":"monitor_lanip","action":"show","param":{"TYPE":"data,total","ORDER_BY":"ip_addr_int","orderType":"IP","limit":"0,100","ORDER":""}}
    res = ikuai_call(data)
    if not res: return registry
    res = res["data"]
    upload      = prom.Gauge('ikuai_client_upload', '接口实时上传', ["ip_addr", "mac", "hostname", "client_type", "comment"], registry=registry)
    download    = prom.Gauge('ikuai_client_download', '接口实时下载', ["ip_addr", "mac", "hostname", "client_type", "comment"], registry=registry)
    total_up    = prom.Gauge('ikuai_client_total_upload', '接口总计上传', ["ip_addr", "mac", "hostname", "client_type", "comment"], registry=registry)
    total_down  = prom.Gauge('ikuai_client_total_download', '接口总计下载', ["ip_addr", "mac", "hostname", "client_type", "comment"], registry=registry)
    connect_num = prom.Gauge('ikuai_client_connect_num', '接口实时下载', ["ip_addr", "mac", "hostname", "client_type", "comment"], registry=registry)
    for r in res:
        upload.labels(r["ip_addr"], r["mac"], r["hostname"], r["client_type"], r["comment"]).set(r["upload"])
        download.labels(r["ip_addr"], r["mac"], r["hostname"], r["client_type"], r["comment"]).set(r["download"])
        total_up.labels(r["ip_addr"], r["mac"], r["hostname"], r["client_type"], r["comment"]).set(r["total_up"])
        total_down.labels(r["ip_addr"], r["mac"], r["hostname"], r["client_type"], r["comment"]).set(r["total_down"])
        connect_num.labels(r["ip_addr"], r["mac"], r["hostname"], r["client_type"], r["comment"]).set(r["connect_num"])
    return registry

def get_protocol(registry):
    name = {
        "Total"    : "合计",
        "Transport": "文件传输",
        "HTTP"     : "HTTP协议",
        "Download" : "网络下载",
        "Unknown"  : "未知应用",
        "Video"    : "网络视频",
        "IM"       : "网络通讯",
        "Others"   : "其他应用",
        "Test"     : "测速软件",
        "Common"   : "常用协议",
        "Game"     : "网络游戏",
    }
    # 流量/连接数分布
    data = {"func_name":"monitor_system","action":"show","param":{"TYPE":"app_flow","minute":30}}
    res = ikuai_call(data)
    if not res: return registry
    res = res["app_flow"][0]
    appflow = prom.Gauge(f'ikuai_protocol_appflow', f'流量分布', ["name_en", "name_cn"], registry=registry)
    for k, v in res.items():
        appflow.labels(k, name[k]).set(v)
    # 协议速率
    data = {"func_name":"monitor_app_flow","action":"show","param":{"TYPE":"flow"}}
    res = ikuai_call(data)
    if not res: return registry
    res = res["data"]
    upload         = prom.Gauge(f'ikuai_protocol_app_stream_upload', f'协议实时上传', ["name_en", "name_cn"], registry=registry)
    download       = prom.Gauge(f'ikuai_protocol_app_stream_download', f'协议实时下载', ["name_en", "name_cn"], registry=registry)
    total_upload   = prom.Gauge(f'ikuai_protocol_app_stream_total_up', f'协议总计上传', ["name_en", "name_cn"], registry=registry)
    total_download = prom.Gauge(f'ikuai_protocol_app_stream_total_download', f'协议总计下载', ["name_en", "name_cn"], registry=registry)
    total          = prom.Gauge(f'ikuai_protocol_app_stream_total', f'协议总计速率', ["name_en", "name_cn"], registry=registry)
    connect_num    = prom.Gauge(f'ikuai_protocol_app_stream_connect_num', f'协议连接数', ["name_en", "name_cn"], registry=registry)
    for r in res:
        upload.labels(r["app_name"], name[r["app_name"]]).set(r["upload"])
        download.labels(r["app_name"], name[r["app_name"]]).set(r["download"])
        total_upload.labels(r["app_name"], name[r["app_name"]]).set(r["total_up"])
        total_download.labels(r["app_name"], name[r["app_name"]]).set(r["total_down"])
        total.labels(r["app_name"], name[r["app_name"]]).set(r["total"])
        connect_num.labels(r["app_name"], name[r["app_name"]]).set(r["connect_num"])
    return registry

def get_sys_stat(registry):
    data = {"func_name":"homepage","action":"show","param":{"TYPE":"sysstat"}}
    res = ikuai_call(data)
    if not res: return registry
    res = res["sysstat"]
    for k, v in res.items():
        if k == "cpu": prom.Gauge(f'ikuai_sys_stat_cpu_used', f'CPU使用率', registry=registry).set(float(v[0].replace("%", "")))
        if k == "cputemp": prom.Gauge(f'ikuai_sys_stat_cpu_temp', f'CPU温度', registry=registry).set(v[0])
        if k == "memory":
            memory = prom.Gauge(f'ikuai_sys_stat_memory', f'内存信息', ["type"], registry=registry)
            memory.labels("total").set(v["total"])
            memory.labels("available").set(v["available"])
            memory.labels("free").set(v["free"])
            memory.labels("cached").set(v["cached"])
            memory.labels("buffers").set(v["buffers"])
            memory.labels("used").set(float(v["used"][0].replace("%", "")))
        if k == "stream":
            stream  = prom.Gauge(f'ikuai_sys_stat_stream', f'系统实时流量', ["type"], registry=registry)
            stream.labels("connect_num").set(v["connect_num"])
            stream.labels("upload").set(v["upload"])
            stream.labels("download").set(v["download"])
            stream.labels("total_up").set(v["total_up"])
            stream.labels("total_down").set(v["total_down"])
    return registry

app = Flask(__name__)

@app.route('/ping')
def ping():
    return "pong"

@app.route("/metrics")
def metrics():
    registry = prom.CollectorRegistry()
    registry = get_ikuai_version(registry)
    registry = get_iface_stream(registry)
    registry = get_client_stream(registry)
    registry = get_protocol(registry)
    registry = get_sys_stat(registry)
    return Response(prom.generate_latest(registry), mimetype="text/plain")

# APP调试模式
APP_DEBUG = True

if __name__ == '__main__':
    app.run("0.0.0.0", 9000, APP_DEBUG)