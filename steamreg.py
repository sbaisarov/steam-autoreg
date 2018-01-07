import requests
import time
import string
import random
import re
import json
import logging

from bs4 import BeautifulSoup

from steampy.client import SteamClient
from steampy import guard
from tempmail import TempMail

logger = logging.getLogger('__main__')


class SteamAuthError(Exception): pass
class SteamCaptchaError(Exception): pass
class RuCaptchaError(Exception): pass


class SteamRegger:

    def __init__(self, proxy=None):
        self.proxy = proxy
        self.email = None

    @staticmethod
    def handle_request(session, url, data={}, timeout=30):
        while True:
            try:
                resp = session.post(url, data=data, timeout=timeout).json()
                return resp
            except requests.exceptions.Timeout as err:
                logger.error('%s %s', err, url)
            except json.decoder.JSONDecodeError as err:
                logger.error('%s %s', err, url)

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

    def addphone_request(self, steam_client, phone_num):
        sessionid = steam_client.session.cookies.get(
                    'sessionid', domain='steamcommunity.com')
        data = {
            'op': 'add_phone_number',
            'arg': phone_num,
            'sessionid': sessionid
        }
        is_valid_number = True
        response = self.handle_request(steam_client.session,
                                       'https://steamcommunity.com/steamguard/phoneajax', data=data)
        logger.info(str(response))
        return response

    def is_phone_attached(self, steam_client):
        sessionid = steam_client.session.cookies.get(
                    'sessionid', domain='steamcommunity.com')
        data = {
            'op': 'has_phone',
            'arg': None,
            'sessionid': sessionid
        }
        while True:
            try:
                response = self.handle_request(steam_client.session,
                    'https://steamcommunity.com/steamguard/phoneajax', data=data)
                break
            except json.decoder.JSONDecodeError as err:
                logger.error(err)
                time.sleep(3)

        return response['has_phone']

    def checksms_request(self, steam_client, sms_code):
        sessionid = steam_client.session.cookies.get(
                    'sessionid', domain='steamcommunity.com')
        data = {
            'op': 'check_sms_code',
            'arg': sms_code,
            'sessionid': sessionid
        }
        response = self.handle_request(
            steam_client.session, 'https://steamcommunity.com/steamguard/phoneajax', data=data)
        logger.info(str(response))
        return response

    def add_authenticator_request(self, steam_client):
        device_id = guard.generate_device_id(steam_client.oauth['steamid'])
        while True:
            try:
                mobguard_data = self.handle_request(steam_client.session,
                    'https://api.steampowered.com/ITwoFactorService/AddAuthenticator/v0001/',
                    data = {
                        "access_token": steam_client.oauth['oauth_token'],
                        "steamid": steam_client.oauth['steamid'],
                        "authenticator_type": "1",
                        "device_identifier": device_id,
                        "sms_phone_id": "1"
                    })['response']
            except json.decoder.JSONDecodeError:
                time.sleep(3)
                continue
            logger.info(str(mobguard_data))
            if mobguard_data['status'] not in (1, 2):
                time.sleep(5)
                continue
            break

        mobguard_data['device_id'] = device_id
        mobguard_data['Session'] = {}
        mobguard_data['Session']['WebCookie'] = None
        for mafile_key, resp_key in (('SteamID', 'steamid'), ('OAuthToken', 'oauth_token')):
            mobguard_data['Session'][mafile_key] = steam_client.oauth[resp_key]

        for mafile_key, resp_key in (
                ('SessionID', 'sessionid'),
                ('SteamLogin', 'steamLogin'),
                ('SteamLoginSecure', 'steamLoginSecure')):
            mobguard_data['Session'][mafile_key] = steam_client.session.cookies[resp_key]

        return mobguard_data

    def finalize_authenticator_request(self, steam_client, mobguard_data, sms_code):
        one_time_code = guard.generate_one_time_code(mobguard_data['shared_secret'], int(time.time()))
        data= {
            "steamid": steam_client.oauth['steamid'],
            "activation_code": sms_code,
            "access_token": steam_client.oauth['oauth_token'],
            'authenticator_code': one_time_code,
            'authenticator_time': int(time.time())
        }
        while True:
            try:
                fin_resp = self.handle_request(steam_client.session,
                    'https://api.steampowered.com/ITwoFactorService/FinalizeAddAuthenticator/v0001/',
                    data=data)['response']
            except json.decoder.JSONDecodeError as err:
                logger.error("json error in the FinalizeAddAuthenticator request")
                time.sleep(3)
                continue
            logger.info(str(fin_resp))
            if (fin_resp.get('want_more') or fin_resp['status'] == 88):
                time.sleep(5)
                continue
            elif fin_resp['status'] == 2:
                fin_resp['success'] = True
            break

        return fin_resp['success']

    def make_account_unlimited(self, mobguard_data, wallet_code, get_api_key=False):
        steam_client = SteamClient()
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

    def create_account(self, rucaptcha_api_key, thread_lock):
        def generate_credential(start, end, uppercase=True):
            random.shuffle(char_sets)
            func = lambda x: ''.join((random.choice(x) for _ in range(random.randint(start, end))))
            credential = ''.join(map(func, char_sets))
            if not uppercase:
                credential = credential.lower()
            return credential

        def generate_captcha():
            gid = session.get('https://store.steampowered.com/join/refreshcaptcha/?count=1',
                               headers={'Host': 'store.steampowered.com'}, timeout=10).json()['gid']
            captcha_img = session.get('https://store.steampowered.com/public/captcha.php?gid={}'
                                      .format(gid), timeout=30).content
            resp = requests.post('http://rucaptcha.com/in.php',
                                 files={'file': ('captcha', captcha_img, 'image/png')},
                                 data={'key': rucaptcha_api_key},
                                 timeout=30)

            captcha_id = resp.text.partition('|')[2]
            return captcha_id, gid

        def send_captcha(captchagid, captcha_text, email):
            data = {
                'captchagid': captchagid,
                'captcha_text': captcha_text,
                'email': email,
                'count': '1'
            }
            resp = self.handle_request(session, 'https://store.steampowered.com/join/verifycaptcha',
                                       data=data)
            logger.info(resp)
            return resp

        def resolve_captcha(captcha_id, gid):
            attempts = 10
            while True:
                time.sleep(10)
                r = requests.post('http://rucaptcha.com/res.php?key={}&action=get&id={}'
                                  .format(rucaptcha_api_key, captcha_id), timeout=30)
                logger.info(r.text)
                if 'CAPCHA_NOT_READY' in r.text:
                    continue
                elif 'ERROR_CAPTCHA_UNSOLVABLE' in r.text:
                    return None
                break
            resolved_captcha = r.text.partition('|')[2].replace('amp;', '')
            return resolved_captcha

        def generate_login_name():
            while True:
                login_name = generate_credential(2, 4, uppercase=False)
                r = self.handle_request(session, 'https://store.steampowered.com/join/checkavail/?accountname={}&count=1'
                                                 .format(login_name))
                logger.info(str(r))
                if r['bAvailable']:
                    return login_name
                time.sleep(3)

        logger.info("Hello!")
        session = requests.Session()
        if self.proxy:
            session.proxies.update(self.proxy)
        session.headers.update({'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36'),
                                'Accept-Language': 'q=0.8,en-US;q=0.6,en;q=0.4'})

        char_sets = [string.ascii_lowercase, string.digits, string.ascii_uppercase]
        while True:
            captcha_id, gid = generate_captcha()
            captcha_text = resolve_captcha(captcha_id, gid)
            if not captcha_text:
                continue
            login_name = generate_login_name()
            password = generate_credential(2, 4)
            with thread_lock:
                self.email, tm_object = self.generate_mailbox()
            logger.info("Email box: %s", self.email)
            logger.info("Resolving captcha... %s", login_name)
            resp = send_captcha(gid, captcha_text, self.email)
            if not resp['bCaptchaMatches']:
                logger.info("Captcha text is wrong: %s", captcha_text)
                requests.post('http://rucaptcha.com/res.php?key={}&action=reportbad&id={}'
                              .format(rucaptcha_api_key, captcha_id), timeout=30)
            elif not resp['bEmailAvail']:
                logger.info("Email box is already used: %s", self.email)
            else:
                break

        logger.info("Confirming email... %s", login_name)
        with thread_lock:
            creationid = self.confirm_email(tm_object, self.email, login_name, gid, captcha_text)
        logger.info("Email confirmed: %s %s", self.email, login_name)

        data = {
            'accountname': login_name,
            'password': password,
            'email': self.email,
            'captchagid': gid,
            'captcha_text': captcha_text,
            'i_agree': '1',
            'ticket': '',
            'count': '32',
            'lt': '0',
            'creation_sessionid': creationid
        }
        resp = self.handle_request(session, 'https://store.steampowered.com/join/createaccount/',
                                   data=data, timeout=25)
        logger.info('create account response: %s', resp)

        return login_name, password

    @staticmethod
    def generate_mailbox():
        resp = requests.get('https://temp-mail.ru/option/change', timeout=30)
        available_domains = re.findall(r'<option value=".+">(.+)</option>', resp.text)
        domain = random.choice(available_domains)
        tm = TempMail(domain=domain)
        mailbox = tm.generate_login() + domain
        return mailbox, tm

    @staticmethod
    def confirm_email(tm_object, mailbox, login_name, captchagid, captca_text):
        params = {
            'accountname': login_name,
            'email': mailbox,
            'captchagid': captchagid,
            'captcha_text': captca_text
        }
        resp = requests.get('https://store.steampowered.com/join/ajaxverifyemail',
                            params=params, timeout=30).json()
        logger.info("ajax verify email response: %s", resp)
        creationid = resp['sessionid']
        attempts = 0
        while attempts < 8:
            time.sleep(3)
            try:
                resp = tm_object.get_mailbox(mailbox)[0]
                break
            except KeyError as err:
                logger.info("Waiting for the email... %s", mailbox)
            attempts += 1

        verification_link = re.search(r'https:\/\/store.steampowered.com.+creationid=\d+', resp['mail_text_only']).group()
        requests.get(verification_link, timeout=30)
        requests.get('http://api.temp-mail.ru/request/delete/id/%s' % resp['mail_id'], timeout=30)

        return creationid

    @staticmethod
    def activate_account(steam_client):
        url = 'https://steamcommunity.com/profiles/{}/edit'.format(steam_client.steamid)
        data = {
            'sessionID': steam_client.get_session_id(),
            'type': 'profileSave',
            'personaName': steam_client.login_name,
            'summary': 'No information given.',
            'primary_group_steamid': '0'
        }
        steam_client.session.post(url, data=data, timeout=30)

    @staticmethod
    def remove_intentory_privacy(steam_client):
        url = 'http://steamcommunity.com/profiles/{}/edit/settings'.format(steam_client.steamid)
        data = {
            'sessionID': steam_client.get_session_id(),
            'type': 'profileSettings',
            'privacySetting': '3',
            'commentSetting': 'commentanyone',
            'inventoryPrivacySetting': '3',
            'inventoryGiftPrivacy': '1',
        }
        steam_client.session.post(url, data=data, timeout=30)

    @staticmethod
    def fetch_tradeoffer_link(steam_client):
        url = 'http://steamcommunity.com/profiles/%s/tradeoffers/privacy' % steam_client.steamid
        resp = steam_client.session.get(url, timeout=30)
        regexr = 'https:\/\/steamcommunity.com\/tradeoffer\/new\/\?partner=.+&token=.+(?=" )'
        try:
            return re.search(regexr, resp.text).group()
        except AttributeError as err:
            logger.error("Failed to fetch offer link %s", err)
            return ''


if __name__ == '__main__':
    foo = SteamRegger()
    login, passwd, session = foo.create_account()
    sessionid = session.cookies.get('sessionid', domain='store.steampowered.com')
    print(sessionid)
