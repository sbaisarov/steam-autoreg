import requests
import datetime
import base64
import time
import string
import random
import re
import json
import logging

from bs4 import BeautifulSoup

from steampy.client import SteamClient
from steampy import guard

logger = logging.getLogger(__name__)

class SteamAuthError(Exception): pass
class SteamCaptchaError(Exception): pass

class SteamRegger:

	def __init__(self, proxy=None):
		self.proxy = proxy


	def registrate_account(self):
		mafile = {}
		login_name, password = self.create_account()
		steam_client, mobguard_data = self.add_authenticator(login_name, password)

		r = steam_client.session.get('https://steamcommunity.com/my/tradeoffers/privacy')
		s = BeautifulSoup(r.text, 'html.parser')
		trade_url = s.find(id='trade_offer_access_url')['value']

		mafile['account_password'] = password
		mafile['trade_url'] = trade_url
		mafile['turnover'] = 0
		mafile['reg_ip'] = self.proxy
		mafile.update(mobguard_data)
		logger.info(mafile)

		return mafile


	def mobile_login(self, login_name, password, email=None, email_passwd=None):
		steam_client = SteamClient(None, self.proxy)
		resp = steam_client.mobile_login(login_name, password, None, email, email_passwd)
		resp_message = resp.get('message', None)
		if resp_message:
			if 'Please verify your humanity' in resp_message:
				raise SteamCaptchaError('Слишком много неудачных входов в аккаунты, '
										'Steam требует решить капчу.')
			elif 'name or password that you have entered is incorrect' in resp_message:
				raise SteamAuthError('Неверный логин или пароль: ' + login_name)

		if resp['requires_twofactor']:
			raise SteamAuthError('К аккаунту уже привязан Guard: ' + login_name)

		if resp.get('emailauth_needed', None):
			raise SteamAuthError('К аккаунту привязан Mail Guard. '
								 'Почта и пароль от него не предоставлены')


		if not steam_client.oauth:
			error = 'Не удалось залогиниться в аккаунт: {}:{}'.format(
						login_name, password)
			raise SteamAuthError(error)

		return steam_client


	@staticmethod
	def steam_addphone_request(steam_client, phone_num):
		sessionid = steam_client.session.cookies.get(
					'sessionid', domain='steamcommunity.com')
		data = {
		'op': 'add_phone_number',
		'arg': phone_num,
		'sessionid': sessionid
		}
		is_valid_number = True
		while True:
			response = steam_client.session.post(
				'https://steamcommunity.com/steamguard/phoneajax', data=data).json()
			logger.info(str(response))
			if not response['fatal']:
				if 'that phone number is not usable' in response.get('error_text', ''):
					is_valid_number = False
				break

		return is_valid_number


	@staticmethod
	def has_phone_attached(steam_client):
		sessionid = steam_client.session.cookies.get(
					'sessionid', domain='steamcommunity.com')
		data = {
		'op': 'has_phone',
		'arg': None,
		'sessionid': sessionid
		}
		response = steam_client.session.post(
			'https://steamcommunity.com/steamguard/phoneajax', data=data).json()
		return response['has_phone']


	@staticmethod
	def steam_checksms_request(steam_client, sms_code):
		sessionid = steam_client.session.cookies.get(
					'sessionid', domain='steamcommunity.com')
		data = {
		'op': 'check_sms_code',
		'arg': sms_code,
		'sessionid': sessionid
		}
		attempts = 0
		while attempts < 10:
			response = steam_client.session.post(
				'https://steamcommunity.com/steamguard/phoneajax', data=data)
			logger.info(response.text)
			if not response.json()['fatal']:
				break
			time.sleep(3)
			attempts += 1

		if response.json()['fatal'}]:
			raise SteamAuthError('Steam Service is not available at the moment')

		return response.json()['success']

	@staticmethod
	def steam_add_authenticator_request(steam_client):
		device_id = guard.generate_device_id(steam_client.oauth['steamid'])
		while True:
			try:
				mobguard_data = steam_client.session.post(
					'https://api.steampowered.com/ITwoFactorService/AddAuthenticator/v0001/',
					data = {
					"access_token": steam_client.oauth['oauth_token'],
			        "steamid": steam_client.oauth['steamid'],
			        "authenticator_type": "1",
			        "device_identifier": device_id,
			        "sms_phone_id": "1"
			        }).json()['response']
				logger.info(str(mobguard_data))
				if mobguard_data['status'] == 84:
					time.sleep(5)
					continue
				break
			except json.decoder.JSONDecodeError:
				pass

		mobguard_data['device_id'] = device_id
		mobguard_data['Session'] = {}
		mobguard_data['Session']['WebCookie'] = None
		for mafile_key, resp_key in (('SteamID', 'steamid'), ('OAuthToken', 'oauth_token')):
			mobguard_data['Session'][mafile_key] = steam_client.oauth[resp_key]

		for mafile_key, resp_key in (('SessionID', 'sessionid'),
				('SteamLogin', 'steamLogin'), ('SteamLoginSecure', 'steamLoginSecure')):
			mobguard_data['Session'][mafile_key] = steam_client.session.cookies[resp_key]

		return mobguard_data


	@staticmethod
	def steam_finalize_authenticator_request(steam_client, mobguard_data, sms_code):
		one_time_code = guard.generate_one_time_code(mobguard_data['shared_secret'], int(time.time()))
		while True:
			try:
				fin_resp = steam_client.session.post(
					'https://api.steampowered.com/ITwoFactorService/FinalizeAddAuthenticator/v0001/',
					data={
					"steamid": steam_client.oauth['steamid'],
					"activation_code": sms_code,
					"access_token": steam_client.oauth['oauth_token'],
					'authenticator_code': one_time_code,
					'authenticator_time': int(time.time())
					}).json()['response']
				logger.info(str(fin_resp))
				if (fin_resp.get('want_more') or
					fin_resp['status'] == 88):
					time.sleep(5)
					continue
				break
			except json.decoder.JSONDecodeError:
				pass

		return fin_resp['success']

	def make_account_unlimited(self, mobguard_data, wallet_code, get_api_key=False):
		steam_client = SteamClient(None, self.proxy)
		steam_client.login(mobguard_data['account_name'], mobguard_data['account_password'], mobguard_data)
		data = {
		'wallet_code': wallet_code,
		'CreateFromAddress': '1',
		'Address': 'Russia',
		'City': 'Russia',
		'Country': 'RU',
		'State': '',
		'PostCode': '0001'
		}
		steam_client.session.post('https://store.steampowered.com/account/validatewalletcode/',
						   		  data={'wallet_code': wallet_code})
		steam_client.session.post('https://store.steampowered.com/account/createwalletandcheckfunds/',
						   		  data=data)
		steam_client.session.post('https://store.steampowered.com/account/confirmredeemwalletcode/',
								  data={'wallet_code': wallet_code})

		if get_api_key:
			sessionid = steam_client.session.cookies.get(
						'sessionid', domain='steamcommunity.com')
			data = {
			'domain': 'domain.com',
			'agreeToTerms': 'agreed',
			'sessionid': sessionid,
			'Submit': 'Register'
			}
			time.sleep(10)
			r = steam_client.session.post('https://steamcommunity.com/dev/registerkey', data=data)
			key = re.search('Key: (.+)</p', r.text).group(1)
			return key


	def create_account(self):
		def credential_generator(chr_sets):
			random.shuffle(chr_sets)
			credential = ''.join(map(func, chr_sets))
			yield credential


		def resolve_captcha():
			def generate_captcha():
				gid = session.get('https://store.steampowered.com/join/refreshcaptcha/?count=1',
								   headers={'Host': 'store.steampowered.com'}).json()['gid']
				captcha_img = session.get('https://store.steampowered.com/public/captcha.php?gid={}'.format(gid)).content
				captcha_id = requests.post('http://rucaptcha.com/in.php',
								   		   files={'file': ('captcha', captcha_img, 'image/png')},
								   		   data={'key': 'ac530c64ce7abad34972decbece2c844'}).text.partition('|')[2]
				return captcha_id, gid

			captcha_id, gid = generate_captcha()
			rucaptcha_key = 'ac530c64ce7abad34972decbece2c844'

			while True:
				time.sleep(10)
				r = requests.post(
						'http://rucaptcha.com/res.php?key={}&action=get&id={}'
						.format(rucaptcha_key, captcha_id))
				logger.info(r.text)
				if 'CAPCHA_NOT_READY' in r.text:
					continue
				elif 'ERROR_CAPTCHA_UNSOLVABLE' in r.text:
					captcha_id, gid = generate_captcha()
					continue
				break
			resolved_captcha = r.text.partition('|')[2].replace('amp;', '')
			return resolved_captcha, gid

		session = requests.Session()
		if self.proxy:
			session.proxies.update(self.proxy)
		session.headers.update({'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
	        'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36'),
	        'Accept-Language': 'q=0.8,en-US;q=0.6,en;q=0.4'})
		# generate and check validity of the login name
		chr_sets = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
		func = lambda x: ''.join((random.choice(x) for _ in range(random.randint(2, 4))))
		login_name, password, email = (next(credential_generator(chr_sets)) for _ in range(3))
		email += '@bubblemail.xyz'
		while True:
			r = session.post(
				'https://store.steampowered.com/join/checkavail/?accountname={}&count=1'.format(login_name)).json()
			logger.info(str(r))
			if r['bAvailable']:
				break
			else:
				login_name = next(credential_generator(chr_sets))
		while True:
			captcha, gid = resolve_captcha()
			data = {
			'accountname': login_name,
			'password': password,
			'email': email,
			'captchagid': gid,
			'captcha_text': captcha,
			'i_agree': '1',
			'ticket': '',
			'count': '32',
			'lt': '0'
			}
			try:
				resp = session.post('https://store.steampowered.com/join/createaccount/',
									data=data).json()
			except json.decoder.JSONDecodeError:
				continue
			if resp['bSuccess']:
				break
			logger.info('The resolved captcha is wrong, trying again...')
		return login_name, password
