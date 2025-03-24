import configparser
import json
import os
import re
import shutil
import time
from datetime import datetime, timedelta

from DrissionPage import Chromium

# 创建ConfigParser对象
config = configparser.ConfigParser()
# 读取INI文件
config.read('config.ini', encoding='utf-8')


def get_apt_data(api_token : str):
	# 态势感知接口地址
	url = f'{config.get('browser', 'url')}/risk/getRiskList'
	# 请求头
	headers = {
		'Authorization': 'Bearer ' + api_token,
	}

	# 获取当前的日期和时间
	now = datetime.now()
	# 计算昨天的日期和时间
	yesterday = now - timedelta(days=1)
	# 获取当前年份
	year = now.year
	# 获取当前月份，以两位数字格式表示
	month = now.strftime('%m')
	# 获取当前日期，以两位数字格式表示
	day = now.strftime('%d')
	# 获取昨天的年份
	yesterday_year = yesterday.year
	# 获取昨天的月份，以两位数字格式表示
	yesterday_month = yesterday.strftime('%m')
	# 获取昨天的日期，以两位数字格式表示
	yesterday_day = yesterday.strftime('%d')
	# 构造查询的开始时间，格式为 "YYYY-MM-DD 19:00:00"，时间为昨天的19:00:00
	start_time = f"{yesterday_year}-{yesterday_month}-{yesterday_day} 19:00:00"
	# 构造查询的结束时间，格式为 "YYYY-MM-DD 23:59:59"，时间为今天的23:59:59
	end_time = f"{year}-{month}-{day} 23:59:59"
	# 如果 config.ini 里留空，没有配置起始和终止时间，就默认是前一天晚上 19 点到查询到当日晚 23 点 59 分 59 秒
	if config.get('apt', 'start_time'):
		start_time = config.get('apt', 'start_time')
	if config.get('apt', 'end_time'):
		end_time = config.get('apt', 'end_time')

	# 请求体
	post_data = {"limit":80,"offset":0,"total":None,"queryId":None,"maxaccessid":None,"assetChildNodes":[],"combined":1,"attackgrades":None,"attackstatuss":None,"original":None,
				 "accesssubtype": json.loads(config.get('apt', 'accesssubtype')),
				 "flags": json.loads(config.get('apt', 'flags')),
				 "sips":[],"dips":[],"assetOrganize":None,"apptypeids":[],"eventypes":[],"incidentids":[],"pstates":[0],"poid":"","replycode":"","cve":"","ruleid":"","domain":"","cnnvd":"","pcapId":"","ioctagtypes":None,"oobcontent":"","payload":"","attackerip":"",
				 "begin":start_time,"end":end_time,"nonflags":[],"fromtype":None,"direction":None}

	response = tab.post(url, headers=headers, json=post_data, verify=False)
	# 将响应内容解析为可操作键值对的 dict 格式，原生的 json 是 str 格式(即 response.text)
	# 库在内部实现了 json 的 str 到 python 的 dict 对象解析过程
	response_json = response.json()
	return response_json

def deal_with_apt(apt_data : json):
	seen_combinations = {}
	diy_list = []

	for i in apt_data:
		# 事件名称,从名称中提取被 【】 标记的关键部分，若无标记则保留原名
		name_match = re.search(r'【(.*?)】', i.get('name'))
		name = name_match.group(1) if name_match else i.get('name')
		# 事件详情
		signame = i.get('signame')
		# 事件时间
		date_time = i.get('datetime')
		# 事件状态
		attackStatusName = i.get('attackStatusName')
		# 响应码
		replycode = i.get('replycode')
		# 载荷
		payload = i.get('payload')

		# 源
		sip = i.get('sip')
		sport = i.get('sport')
		sipplace = i.get('sipplace')

		# 目
		dip = i.get('dip')
		dport = i.get('dport')
		dipplace = i.get('dipplace')
		domain = i.get('domain')

		# 使用元组作为字典的键来确保其不可变性
		key = (name, signame, replycode, payload, sip, dip)
		if key not in seen_combinations:
			seen_combinations[key] = True
			diy_list.append({
				'name': name,
				'signame': signame,
				'payload': payload,
				'date_time': date_time,
				'attackStatusName': attackStatusName,
				'replycode': replycode,
				'sip': sip,
				'sport': sport,
				'sipplace': sipplace,
				'dip': dip,
				'dport': dport,
				'dipplace': dipplace,
				'domain': domain
			})
	return diy_list

if __name__ == '__main__':
	# 指定端口启动链接浏览器，如果路径中没找到浏览器可执行文件，Windows 系统下程序会在注册表中查找路径
	browser = Chromium(config.getint('browser', 'port'))
	# 获取标签页对象
	tab = browser.latest_tab
	# 访问态势感知地址
	tab.get(config.get('browser', 'url'))

	# 等待手动登录成功后，获取token
	while True:
		token = tab.local_storage('APT_token').strip('"')
		# 正常 token 长度是 280
		if len(token) < 280 :
			time.sleep(5)
			continue
		break

	# 利用 token 获取原始数据
	apt_json = get_apt_data(token)['data']['data']
	# 写入处理后的数据到 apt.json 里
	with open(os.path.join(os.path.dirname(__file__), 'apt.json'), 'w', encoding='utf-8') as file:
		# TextIO 本身实现了 SupportsWrite[str] 协议
		json.dump(deal_with_apt(apt_json), file, ensure_ascii=False)
	# 第一次运行先生成一次 apt.json.old
	shutil.copy(os.path.join(os.path.dirname(__file__), 'apt.json'), os.path.join(os.path.dirname(__file__), 'apt.json.old'))

	# 轮询外发
	while True:
		# 利用 token 获取原始数据
		apt_json = get_apt_data(token)['data']['data']
		# 写入处理后的数据到 apt.json 里
		with open(os.path.join(os.path.dirname(__file__), 'apt.json'), 'w', encoding='utf-8') as file:
			# TextIO 本身实现了 SupportsWrite[str] 协议
			json.dump(deal_with_apt(apt_json), file, ensure_ascii=False)
			# 读取当前数据
			current_apt = deal_with_apt(apt_json)
		# 读取上一次的数据
		with open(os.path.join(os.path.dirname(__file__), 'apt.json.old'), 'r', encoding='utf-8') as file:
			previous_apt = json.load(file)
		# 找出新增的事件
		new_events = [event for event in current_apt if event not in previous_apt]
		# 发送新增事件到企业微信
		for event in new_events:
			wx_header = {'Content-Type': 'application/json'}
			wx_json = {
				"msgtype": "markdown",
				"markdown": {
					"content": f"事件：{event['name']}\n"
							   f"`{event['signame']}`\n"
							   f"时间：{event['date_time']}\n"
							   f"状态：{event['attackStatusName']}\n"
							   f"响应码：{event['replycode']}\n"
							   f"`{event['payload']}`\n"
							   f"源IP：{event['sip']}\n"
							   f"源端口：{event['sport']}\n"
							   f"源位置：{event['sipplace']}\n"
							   f"目的IP：{event['dip']}\n"
							   f"目的端口：{event['dport']}\n"
							   f"目的位置：{event['dipplace']}\n"
							   f"域名：{event['domain']}"
				}
			}
			# 通过 webhook 发到企业微信
			wx_response = tab.post(config.get('browser', 'webhook_url'), headers=wx_header, json=wx_json, verify=False)
			# 打印企业微信返回的响应
			print(wx_response.text)
		# 更新 apt.json.old
		shutil.copy(os.path.join(os.path.dirname(__file__), 'apt.json'),
					os.path.join(os.path.dirname(__file__), 'apt.json.old'))
		# 休眠
		time.sleep(config.getint('apt', 'sleep_time'))
		# 打印当前时间
		print(datetime.now())