# @Author   : ranyijun
# @time     : 2023/02/25
# @File     : read_vul_uniontech.py
# @Software : PyCharm

# @fixed_Author : ranyijun@uniontech.com
# @fixed_time	: 2023/02/28

# _*_ coding: utf-8 _*_
#include ./bin/python3
# !./bin/python3


"""
## 脚本功能说明
1.爬取vul.uniontech.com站点以下版本的漏洞信息
1）桌面专业版
2）服务器企业版
3）行业版a
4）行业版c
5）欧拉版

## 脚本功能列举
1.读取指定文本文件，提取CVE编号。
2.CVE编号自动变成大写。
3.自动去重CVE编号。
4.CVE编号查询为空时，在屏幕上红色高亮打印标记出来。(X)
5.对查询的结果做验证，将要查询的编号与结果中的编号进行对比，完全一致才保留结果。
避免出现查询CVE-2021-3347，返回结果是CVE-2021-33477/CVE-2021-33479。
6.CVE编号查询成功和失败数量统计。
7.优化查询结果验证，查询CVE-2018-1311，返回结果是CVE-2018-1311和CVE-2018-13112，只取正确结果CVE-2018-1311。
8.爬取数据结果中，只保存“cveid, source, fixed_version, score, status”字段的数据，并自动调整列宽。
9.优化了vul平台的登陆功能，舍弃了selenium库，使用公钥加密的方式登陆。
"""
import tempfile
from urllib.parse import urljoin

import requests
import os
import pandas as pd
from openpyxl.utils import get_column_letter
import numpy as np
import re
import sys
import argparse
import time


def get_cve_number(source_file) -> list:
	"""从给到的文件内容里提取CVE编号"""
	with open(source_file,encoding="utf-8") as f1_obj:
		contents = f1_obj.read()
		#print(contents,"ping------->")

	
	# 定义空列表，用于存储提取的CVE编号
	cve_number = []
	for line in contents.splitlines():
		# re.IGNORECASE 参数用于忽略大小写
		cve = re.findall(r'CVE-\d{4}-\d*', line, re.IGNORECASE)
		# 将小写字母转换成大写字母
		up_cve = [s.upper() for s in cve]
		if len(up_cve) != 0:
			cve_number.extend(up_cve)
			print(up_cve)
		else:
			pass
	# 去重CVE编号，并保留原有顺序
	new_cve = list({}.fromkeys(cve_number).keys())
	return new_cve


def login_vul(uname, pwd):
	"""登录网站并获取cookie和csrf token信息
	"""
	url = 'https://vul.uniontech.com/api/user/login'
	cookies = ''
	token = ''
	with tempfile.TemporaryDirectory(prefix="login_vul_") as dpath:
		pub_file_path = os.path.join(dpath, 'pub.pem')
		uname_file_path = os.path.join(dpath, 'uname')
		pwd_file_path = os.path.join(dpath, 'pwd')
		tmp_file_path = os.path.join(dpath, 'tmp')
		with open(pub_file_path, 'w') as f:
			f.write(r'''
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy6N1ENuzouav9tUfsTH+
8+zeuIWpoGCVjBvxyLaXHdgucnLvZtvUthW4NGW3SgsdOrV6cHPOUy097CAI3V3u
nDfbC16AY9IZn/pKnwLf6JuBhuJYn9gyp5H0QSimIvUcjShNO7owp++DDMI5vz4J
1XMi8xgz5wgb+uZlz+klwFIJgsHeEl6ieX2E8e6GGNA64RYYiw7SPC9zw3ZY323x
WQG7M3Sc7mUsFgAHSguL/yVMO1FgaZBUK2/kRz9hBkjSxUOzWh7J3GFTf2Wk4eLL
nJzp0/aGsg+hlL/egjxWSNMk/9B5k5Bhv6EoF3wBYLbhGX8GbznanI5kCCR33GxD
BQIDAQAB
-----END PUBLIC KEY-----
                ''')
		with open(uname_file_path, 'w') as f:
			f.write(uname)
		with open(pwd_file_path, 'w') as f:
			f.write(pwd)
		uname = os.popen(
			f"openssl rsautl -encrypt -in {uname_file_path} -inkey {pub_file_path} -out {tmp_file_path} -pubin && cat {tmp_file_path}|base64 -w 0").read()
		pwd = os.popen(
			f"openssl rsautl -encrypt -in {pwd_file_path} -inkey {pub_file_path} -out {tmp_file_path} -pubin && cat {tmp_file_path}|base64 -w 0").read()
		# 登录
		resp = requests.post(urljoin(url, "/api/user/login"), json={
			"username": uname,
			"password": pwd
		})

	for name, value in resp.cookies.get_dict().items():
		cookies += f"{name}={value};"
		if name == 'csrftoken':
			token = value

	# data = {
	# 	'Cookie': cookies,
	# 	'X-Csrftoken': token
	# }

	return cookies, token


def query_vul_library(cookie, csrftoken, url, cve_list) -> tuple:
	"""爬取vul.uniontech.com漏洞库站点中的CVE详细信息"""
	cve_item = []  # 用于存储查询的所有CVE漏洞的结果信息
	success_query = []  # 定义success_query 列表用于存储查询成功的CVE编号信息
	fail_query = []  # 定义fail_query 列表用于存储查询失败的CVE编号信息

	# 请求头
	headers = {
		"Cookie": f"{cookie}",
		"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
		"X-CSRFTOKEN": f"{csrftoken}"
	}

	# 开始爬cve的详情
	if len(cve_list) != 0:
		for cve_number in cve_list:
			print(f"要查询的CVE编号为：{cve_number}")

			cve_response1 = requests.get("{}list?page=1&limit=10&cveid__icontains={}&is_installed=&sort=%2Bid".format(url, cve_number), headers=headers)

			# 返回的是json类型数据，使用loads()函数来转化为字典
			#print(cve_response1,"t+++++++++++++++++++++++++++++++++","{}list?page=1&limit=10&cveid__icontains={}&is_installed=&sort=%2Bid".format(url, cve_number))
			result1 = cve_response1.json()
			# result1 = cve_response1.text.encode('utf-8')  # 对返回内容进行编码
			# result1 = json.loads(result1)
			print('漏洞库中查询结果为{}'.format(result1))
			#print("查询结果为：{}".)
			# vul_data 为查询结果中所有的cve信息，数据类型为list
			try:

				vul_data = result1['data']['items']
			except :
				return ("","","")

			# 对查询结果做筛选
			time.sleep(2)
			if len(vul_data) != 0:
				"""在桌面专业版漏洞库中查询CVE漏洞信息"""
				# 校验查询结果中的CVE编号是否与要查询的编号一致，
				# 不允许出现要查的是CVE-2021-3347，结果却查到了CVE-2021-33477 和 CVE-2021-33479。
				# 查询CVE-2018-1311，返回结果是CVE-2018-1311和CVE-2018-13112，只取正确结果CVE-2018-1311。

				# 遍历vul_data，对比查询结果中的CVE编号是否与要查询的CVE编号一致，若一致，则将结果保存。
				for i in vul_data:
					if cve_number == i['cveid']:
						cve_item.append(i)
						success_query.append(cve_number)
						print(f"查询结果中的 {i['cveid']} 与 要查询的 {cve_number} 一致， 保存...")
					else:
						print(f"查询结果中的 {i['cveid']} 与 要查询的 {cve_number} 不一致， 丢弃...")
			else:
				fail_query.append(cve_number)
				print("未在漏洞库中查询到该CVE信息。")
	else:
		print("CVE编号为空，无法查询。")

	return cve_item, success_query, fail_query

def do_score_check(item_l):
	score = item_l["score"]
	if score is None:
		item_l["score"] = "未知"
		return item_l
	score = (float(score))
	# cve漏洞评分转换为中危高危
	if 9 <= score <= 10:
		# 严重
		item_l["score"] = "严重"
	# print()
	elif 7 <= score < 9:
		item_l["score"] = "高危"
	elif 4 <= score < 7:
		# print()
		item_l["score"] = "中危"
	elif 0 <= score < 4:
		# print()
		item_l["score"] = "低危"
	else:
		# 未知
		# print()
		item_l["score"] = "未知"
	return item_l


def replace_char(string, char, index):
	string = list(string)
	string[index] = char
	return ''.join(string)


def do_json(cve_item):
	for item_l in cve_item:
		#print("------->",item_l,"test----------")
		item_l = do_score_check(item_l)
		#score = item_l["score"]


		#修复状态转换
		fix = item_l["status"]
		if fix == "unprocessed":
			item_l["status"] = "未处理"
		elif fix == "fixed":
			item_l["status"] = "已修复"
		elif fix == "processing":
			item_l["status"] = "处理中"
		elif fix == "unaffected":
			item_l["status"] = "不影响"
		elif fix == "postpone":
			item_l["status"] = "延后处理"
		else:
			item_l["status"]="未知"

		""""# 发布状态：UTSA-2023-000328	CVE-2023-0417	服务器D版	wireshark	中危	2023-02-18
		有日期的显示未已发布，没有信息的显示未发布，因此需要判断advisory_send_info的值的字符串是不是能转化成数字，或者判断字符串是不是“历史数据，未修复，已修复”等状态
		"""
		adv_send_info = item_l["advisory_send_info"]
		#accont_nu = 0
		if adv_send_info != "":
			print(item_l["advisory_send_info"])
			#char1 = ""
			#adv_send_info=replace_char(adv_send_info, "", "-")
			adv_send_info=adv_send_info.replace('-','')
			try :
				int(adv_send_info)
				item_l["advisory_send_info"] = "已发布"

			except :
				print(adv_send_info+"--->不能转化成数字，代表没有发布时间，判断没有发布")
				item_l["advisory_send_info"] = "未发布"
			#if adv_send_info

		#if adv_send_info == "历史数据" or adv_send_info == "不受影响" or adv_send_info == "未修复" or

		#上游修复状态
		fixed = item_l["vul_upstream_status"]
		if fixed == "Unfixed":
			item_l["vul_upstream_status"] = "未处理"
		elif fixed == "Fixed":
			item_l["vul_upstream_status"] = "已修复"
		elif fixed == "Unaffected":
			item_l["vul_upstream_status"] = "不影响"
		elif fixed == "Investigation is underway":
			item_l["vul_upstream_status"] = "正在调查"
		else:
			item_l["vul_upstream_status"]="未知"


		#预装状态installed
		if item_l["is_installed"] == "yes":
			item_l["is_installed"] = "预装"
		elif item_l["is_installed"] == "no":
			item_l["is_installed"] = "非预装"
		else:
			item_l["is_installed"] = "未知"
		#if item_l["status"]==unprocessed'
	#print("------->", cve_item, "test----------")
	#'cveid', 'source', 'fixed_version', 'score', 'status', 'is_installed'
		item_cveid = item_l["cveid"]
		item_source = item_l["source"]
		item_fixed_version = item_l["fixed_version"]
		item_score = item_l["score"]
		item_status = item_l["status"]
		item_is_installed = item_l["is_installed"]
		item_vul_upstream_status = item_l["vul_upstream_status"]
		item_vul_upstream_fixed_version = item_l["vul_upstream_fixed_version"]
		item_advisory_send_info = item_l["advisory_send_info"]
		if 'cveid' in item_l:
			item_l.pop("cveid")
			item_l["漏洞编号"] = item_cveid
		if 'source' in item_l:
			item_l.pop("source")
			item_l["源码包名"] = item_source
		if  'fixed_version' in item_l:
			item_l.pop("fixed_version")
			item_l["修复版本"] = item_fixed_version
		if 'score' in item_l:
			item_l.pop("score")
			item_l["漏洞等级"] = item_score
		if 'status' in item_l:
			item_l.pop("status")
			item_l["修复状态"] = item_status
		if 'is_installed' in item_l:
			item_l.pop("is_installed")
			item_l["预装状态"] = item_is_installed
		if 'vul_upstream_status' in item_l:
			item_l.pop("vul_upstream_status")
			item_l["上游修复状态"] = item_vul_upstream_status
		if 'vul_upstream_fixed_version' in item_l:
			item_l.pop("vul_upstream_fixed_version")
			item_l["上游修复版本"] = item_vul_upstream_fixed_version
		if 'advisory_send_info'  in item_l:
			item_l.pop("advisory_send_info")
			item_l['公告状态'] = item_advisory_send_info



	return cve_item






def save_cve_info(cve_item, output_file):
	"""将爬取的CVE信息存入excel表格里"""

	pf = pd.DataFrame(cve_item)

	print('CVE漏洞爬取结果如下：')
	print(pf)
	print("长度为：",len(pf))
	# 打开excel文件
	file_path = pd.ExcelWriter(output_file)

	# 写入文件， 只保存“cveid, source, fixed_version, score, status”字段的数据。
	# pf.to_excel(file_path, columns=['cveid', 'source', 'fixed_version', 'score', 'status'], encoding='utf-8',
	# 			index=False, sheet_name='cve')

	if len(pf) == 0:  # 如果DataFrame为空
		pf.to_excel(file_path, encoding='utf-8', index=False, sheet_name='cve')
	else:
		#pf[['cveid', 'source', 'fixed_version', 'score', 'status', 'is_installed']].to_excel(file_path, encoding='utf-8',
		#			index=False, sheet_name='cve')
		pf[['漏洞编号', '源码包名', '修复版本', '漏洞等级', '修复状态', '预装状态','上游修复状态','上游修复版本','公告状态']].to_excel(file_path,
																							 encoding='utf-8',
																							 index=False,
																							 sheet_name='cve')
		# DataFrame保存为excel并自动设置列宽
		# 计算每列表头的字符宽度
		column_widths = (pf[['漏洞编号', '源码包名', '修复版本', '漏洞等级', '修复状态', '预装状态','上游修复状态','上游修复版本','公告状态']].columns.to_series().apply(lambda x: len(x.encode('utf-8'))).values)

		# 计算每列的最大字符宽度
		max_widths = (pf[['漏洞编号', '源码包名', '修复版本', '漏洞等级', '修复状态', '预装状态','上游修复状态','上游修复版本','公告状态']].astype(str).applymap(lambda x: len(x.encode('utf-8'))).agg(max).values)

		# 取前两者中每列的最大宽度
		widths = np.max([column_widths, max_widths], axis=0)
		# 指定sheet，设置该sheet的每列列宽
		worksheet = file_path.sheets['cve']
		for i, width in enumerate(widths, 1):
			print(f"i:{i}, width:{width}")
			# openpyxl引擎设置字符宽度时会缩水0.5左右个字符，所以干脆+2使左右都空出一个字宽。
			worksheet.column_dimensions[get_column_letter(i)].width = width + 2

	# 保存文件
	file_path.save()
	time.sleep(1)
	file_path.close()
	# 给文件重命名，在文件名后加一个sysinfo字符
	# 例如 outfile 为 result.xlsx，修改为result_kernelinfo.xlsx
	# file = os.path.basename(output_file)
	# file_name = file.split('.')[0]
	# new_filename = file_name + '_kernelinfo'
	# newfile = new_filename + '.xlsx'
	# # 重命名文件
	# os.rename(output_file, newfile)
	print(f"已将爬取的内核漏洞结果保存到{output_file}文件...")



# 定义脚本的参数
def argparseFunc():
	description = "This script is used to get cve information from https://vul.uniontech.com site."
	# 创建一个解析对象.
	# 作用：当调用parser.print_help()或者运行程序时由于参数不正确
	# (此时python解释器其实也是调用了pring_help()方法)时，会打印这些描述信息，
	# 一般只需要传递description参数。
	parser = argparse.ArgumentParser(description=description)
	
	text_help = "输入文件为txt格式， 输入文件路径使用 -i."
	parser.add_argument('-i', '--infile', action='store', help=text_help)
	
	output_help = "The output file, 输出XLSX文件格式. 输出文件路径使用 -o."
	parser.add_argument('-o', '--outfile', action='store', help=output_help)
	
	professional_mode_help = " 桌面专业版本 --pro."
	parser.add_argument('--pro', action='store_true', help=professional_mode_help)
	
	server_ent_mode_help = " 服务器企业版本查询使用 --ent."
	parser.add_argument('--ent', action='store_true', help=server_ent_mode_help)
	
	hangye_a_mode_help = "服务器a版本查询使用 --hya."
	parser.add_argument('--hya', action='store_true', help=hangye_a_mode_help)
	
	hangye_c_mode_help = " 服务器c版本查询使用 --hyc."
	parser.add_argument('--hyc', action='store_true', help=hangye_c_mode_help)
	
	euler_mode_help = "查询服务器e版本查询使用 --euler."
	parser.add_argument('--euler', action='store_true', help=euler_mode_help)
	
	# 参数与值
	args = parser.parse_args()
	# print(args)
	
	return args, parser



