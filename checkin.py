#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'


def load_balance_hash():
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:
		pass
	return None


def save_balance_hash(balance_hash):
	"""保存余额hash"""
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		print(f'Warning: Failed to save balance hash: {e}')


def generate_balance_hash(balances):
	"""生成余额数据的hash"""
	# 将包含 quota 和 used 的结构转换为简单的 quota 值用于 hash 计算
	simple_balances = {k: v['quota'] for k, v in balances.items()} if balances else {}
	balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
	return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def parse_cookies(cookies_data):
	"""解析 cookies 数据"""
	if isinstance(cookies_data, dict):
		return cookies_data

	if isinstance(cookies_data, str):
		cookies_dict = {}
		for cookie in cookies_data.split(';'):
			if '=' in cookie:
				key, value = cookie.strip().split('=', 1)
				cookies_dict[key] = value
		return cookies_dict
	return {}


async def get_waf_cookies_with_playwright(account_name: str, login_url: str, required_cookies: list[str]):
	"""使用 Playwright 获取 WAF cookies（隐私模式）"""
	print(f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')

	async with async_playwright() as p:
		import tempfile

		with tempfile.TemporaryDirectory() as temp_dir:
			context = await p.chromium.launch_persistent_context(
				user_data_dir=temp_dir,
				headless=False,
				user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
				viewport={'width': 1920, 'height': 1080},
				args=[
					'--disable-blink-features=AutomationControlled',
					'--disable-dev-shm-usage',
					'--disable-web-security',
					'--disable-features=VizDisplayCompositor',
					'--no-sandbox',
				],
			)

			page = await context.new_page()

			try:
				print(f'[PROCESSING] {account_name}: Access login page to get initial cookies...')

				await page.goto(login_url, wait_until='networkidle')

				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=5000)
				except Exception:
					await page.wait_for_timeout(3000)

				cookies = await page.context.cookies()

				waf_cookies = {}
				for cookie in cookies:
					cookie_name = cookie.get('name')
					cookie_value = cookie.get('value')
					if cookie_name in required_cookies and cookie_value is not None:
						waf_cookies[cookie_name] = cookie_value

				print(f'[INFO] {account_name}: Got {len(waf_cookies)} WAF cookies')

				missing_cookies = [c for c in required_cookies if c not in waf_cookies]

				if missing_cookies:
					print(f'[FAILED] {account_name}: Missing WAF cookies: {missing_cookies}')
					await context.close()
					return None

				print(f'[SUCCESS] {account_name}: Successfully got all WAF cookies')

				await context.close()

				return waf_cookies

			except Exception as e:
				print(f'[FAILED] {account_name}: Error occurred while getting WAF cookies: {e}')
				await context.close()
				return None


def get_user_info(client, headers, user_info_url: str):
	"""获取用户信息"""
	try:
		response = client.get(user_info_url, headers=headers, timeout=30)

		if response.status_code == 200:
			data = response.json()
			if data.get('success'):
				user_data = data.get('data', {})
				quota = round(user_data.get('quota', 0) / 500000, 2)
				used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
				return {
					'success': True,
					'quota': quota,
					'used_quota': used_quota,
					'display': f':money: Current balance: ${quota}, Used: ${used_quota}',
				}
		return {'success': False, 'error': f'Failed to get user info: HTTP {response.status_code}'}
	except Exception as e:
		return {'success': False, 'error': f'Failed to get user info: {str(e)[:50]}...'}


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
	"""准备请求所需的 cookies（可能包含 WAF cookies）"""
	waf_cookies = {}

	if provider_config.needs_waf_cookies():
		login_url = f'{provider_config.domain}{provider_config.login_path}'
		waf_cookies = await get_waf_cookies_with_playwright(account_name, login_url, provider_config.waf_cookie_names)
		if not waf_cookies:
			print(f'[FAILED] {account_name}: Unable to get WAF cookies')
			return None
	else:
		print(f'[INFO] {account_name}: Bypass WAF not required, using user cookies directly')

	return {**waf_cookies, **user_cookies}


def execute_check_in(client, account_name: str, provider_config, headers: dict):
	"""执行签到请求"""
	print(f'[NETWORK] {account_name}: Executing check-in')

	checkin_headers = headers.copy()
	checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	response = client.post(sign_in_url, headers=checkin_headers, timeout=30)

	print(f'[RESPONSE] {account_name}: Response status code {response.status_code}')

	if response.status_code == 200:
		try:
			result = response.json()
			if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True
			else:
				error_msg = result.get('msg', result.get('message', 'Unknown error'))
				print(f'[FAILED] {account_name}: Check-in failed - {error_msg}')
				return False
		except json.JSONDecodeError:
			# 如果不是 JSON 响应，检查是否包含成功标识
			if 'success' in response.text.lower():
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True
			else:
				print(f'[FAILED] {account_name}: Check-in failed - Invalid response format')
				return False
	else:
		print(f'[FAILED] {account_name}: Check-in failed - HTTP {response.status_code}')
		return False


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
	"""为单个账号执行签到操作"""
	account_name = account.get_display_name(account_index)
	print(f'\n[PROCESSING] Starting to process {account_name}')

	provider_config = app_config.get_provider(account.provider)
	if not provider_config:
		print(f'[FAILED] {account_name}: Provider "{account.provider}" not found in configuration')
		return False, None

	print(f'[INFO] {account_name}: Using provider "{account.provider}" ({provider_config.domain})')

	user_cookies = parse_cookies(account.cookies)
	if not user_cookies:
		print(f'[FAILED] {account_name}: Invalid configuration format')
		return False, None

	all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
	if not all_cookies:
		return False, None

	client = httpx.Client(http2=True, timeout=30.0)

	try:
		client.cookies.update(all_cookies)

		headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
			'Accept': 'application/json, text/plain, */*',
			'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
			'Accept-Encoding': 'gzip, deflate, br, zstd',
			'Referer': provider_config.domain,
			'Origin': provider_config.domain,
			'Connection': 'keep-alive',
			'Sec-Fetch-Dest': 'empty',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Site': 'same-origin',
			provider_config.api_user_key: account.api_user,
		}

		user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
		user_info = get_user_info(client, headers, user_info_url)
		if user_info and user_info.get('success'):
			print(user_info['display'])
		elif user_info:
			print(user_info.get('error', 'Unknown error'))

		if provider_config.needs_manual_check_in():
			success = execute_check_in(client, account_name, provider_config, headers)
			return success, user_info
		else:
			print(f'[INFO] {account_name}: Check-in completed automatically (triggered by user info request)')
			return True, user_info

	except Exception as e:
		print(f'[FAILED] {account_name}: Error occurred during check-in process - {str(e)[:50]}...')
		return False, None
	finally:
		client.close()

def format_notification(results, success_count, total_count, exec_time):
    """
    渲染高颜值的 Markdown 通知内容
    """
    # 1. 头部：标题与时间
    lines = [
        "### 🤖 AnyRouter 签到报告",
        f"> ⏱️ `{exec_time}`",
        ""
    ]

    # 2. 概览：使用进度条或简洁的统计
    fail_count = total_count - success_count
    status_icon = "🟢" if fail_count == 0 else "🔴"
    
    lines.append(f"**📊 运行概览**")
    lines.append(f"{status_icon} 成功: **{success_count}** {'⚠️' if fail_count > 0 else '⚪'} 失败: **{fail_count}**")
    lines.append("---")

    # 3. 详情：卡片式布局
    for res in results:
        # 图标与状态
        icon = "✅" if res['success'] else "❌"
        # 账号名称加粗
        account_line = f"**👤 {res['name']}**"
        
        # 组合第一行
        lines.append(f"{icon} {account_line}")

        # 详情块 (使用引用块增加层次感)
        if res['success']:
            # 格式化金额，保留两位小数，增加货币符号
            quota = f"{res['quota']:.2f}"
            used = f"{res['used']:.2f}"
            lines.append(f"> 💰 余额: **${quota}**")
            lines.append(f"> 📉 已用: ${used}")
        else:
            # 错误信息使用代码块，避免特殊字符破坏格式
            error_msg = res.get('msg', 'Unknown Error')
            lines.append(f"> 🚫 错误: `{error_msg}`")
        
        # 每个账号间增加空行（Gotify中可能需要）
        lines.append("")

    return "\n".join(lines)

async def main():
    """主函数 - 逻辑与渲染分离版"""
    print('[SYSTEM] AnyRouter.top multi-account auto check-in script started')
    exec_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f'[TIME] Execution time: {exec_time}')

    app_config = AppConfig.load_from_env()
    accounts = load_accounts_config()
    
    if not accounts:
        print('[FAILED] Unable to load account configuration')
        sys.exit(1)

    last_balance_hash = load_balance_hash()
    
    # 用于收集所有账号的执行结果，不再直接拼接字符串
    results = [] 
    current_balances = {}
    success_count = 0
    
    # --- 核心执行循环 ---
    for i, account in enumerate(accounts):
        account_name = account.get_display_name(i)
        account_key = f'account_{i + 1}'
        
        # 默认结果模板
        result_data = {
            'name': account_name,
            'success': False,
            'msg': '',
            'quota': 0.0,
            'used': 0.0
        }

        try:
            success, user_info = await check_in_account(account, i, app_config)
            result_data['success'] = success

            if success:
                success_count += 1
                if user_info and user_info.get('success'):
                    # 记录余额数据
                    q = user_info['quota']
                    u = user_info['used_quota']
                    result_data['quota'] = q
                    result_data['used'] = u
                    current_balances[account_key] = {'quota': q, 'used': u}
                else:
                    result_data['msg'] = "Check-in OK but failed to get info"
            else:
                # 提取错误信息
                if user_info:
                    result_data['msg'] = user_info.get('error', 'Unknown error')
                else:
                    result_data['msg'] = "Request failed"
                    
        except Exception as e:
            print(f'[FAILED] {account_name} exception: {e}')
            result_data['success'] = False
            result_data['msg'] = str(e)[:100] # 截断过长的错误信息
            
        results.append(result_data)

    # --- 决策逻辑 ---
    
    # 1. 计算 Hash 判断余额变化
    current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
    balance_changed = False
    
    if current_balance_hash:
        if last_balance_hash is None:
            balance_changed = True
            print('[NOTIFY] First run detected')
        elif current_balance_hash != last_balance_hash:
            balance_changed = True
            print('[NOTIFY] Balance changes detected')
        
        save_balance_hash(current_balance_hash)

    # 2. 判断是否需要推送 (有失败 OR 余额变动)
    has_failures = success_count < len(accounts)
    should_notify = has_failures or balance_changed

    if should_notify:
        print('[NOTIFY] Generating aesthetic notification...')
        notify_content = format_notification(results, success_count, len(accounts), exec_time)
        
        # 打印预览
        print("-" * 30)
        print(notify_content)
        print("-" * 30)
        
        # 推送消息 (确保你的 notify 模块支持 markdown，通常 gotify 默认支持)
        # 建议在 notify.push_message 中显式指定 markdown 格式，如果那是你的库支持的参数
        notify.push_message('AnyRouter Check-in Report', notify_content, msg_type='markdown')
        print('[NOTIFY] Notification sent.')
    else:
        print('[INFO] All successful and no balance change. Silent mode.')

    sys.exit(0 if success_count > 0 else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n[WARNING] Program interrupted by user')
		sys.exit(1)
	except Exception as e:
		print(f'\n[FAILED] Error occurred during program execution: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
