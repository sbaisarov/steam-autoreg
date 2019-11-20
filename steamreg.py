import requests
import time
import string
import random
import re
import json
import io
import logging
import shelve
import imaplib
import collections

from requests.exceptions import Timeout, ConnectionError, ProxyError
from python_anticaptcha import AnticaptchaClient, ImageToTextTask, NoCaptchaTaskProxylessTask

from steampy.client import SteamClient
from steampy.login import CaptchaRequired, AuthException
from steampy.utils import convert_edomain_to_imap
from steampy import guard

from enums import CaptchaService, SelectionType

logger = logging.getLogger('__main__')

class SteamAuthError(Exception): pass
class SteamRuCaptchaError(Exception): pass
class RuCaptchaError(Exception): pass
class LimitReached(Exception): pass
class InvalidEmail(Exception): pass
class AddPhoneError(Exception): pass


class SteamRegger:

    def __init__(self, client):
        logger.info("bla")
        self.client = client
        self.failed_captchas_counter = 0
        self.sucessfull_captchas_counter = 0
        self.captchas_expenses_total = 0

        self.captcha_service = None

        self.counters_db = shelve.open("database/tmplcounters", writeback=True)

        for key in ("login_counters", "password_counters", "nickname_counters"):
            if self.counters_db.get(key) is None:
                self.counters_db[key] = {}

    def set_captcha_service(self):
        api_key = self.client.captcha_api_key.get()
        captcha_host = self.client.captcha_host.get()
        if self.client.captcha_service_type.get() == CaptchaService.RuCaptcha:
            self.captcha_service = RuCaptcha(api_key, captcha_host)
        elif self.client.captcha_service_type.get() == CaptchaService.AntiCaptcha:
            self.captcha_service = AntiCaptcha(api_key, captcha_host)

    @staticmethod
    def request_post(session, url, data={}, headers={}, timeout=30):
        while True:
            try:
                resp = session.post(url, data=data, timeout=timeout, headers=headers, attempts=3).json()
                return resp
            except json.decoder.JSONDecodeError as err:
                logger.error('%s %s', err, url)
            except (Timeout, ConnectionError, ProxyError) as err:
                logger.error('%s %s', err, url)
                if session.proxies:
                    raise err

    @staticmethod
    def request_get(session, url, headers={}, params={}, timeout=30, is_json=False):
        while True:
            try:
                resp = session.get(url, headers=headers, params=params, timeout=timeout, attempts=3)
                if is_json:
                    resp = resp.json()
                return resp
            except json.decoder.JSONDecodeError as err:
                logger.error('%s %s', err, url)
            except (Timeout, ConnectionError, ProxyError) as err:
                logger.error('%s %s', err, url)
                if session.proxies:
                    raise err

    def login(self, login_name, password, proxy=None, email=None, email_passwd=None, pass_login_captcha=False):
        steam_client = SteamClient()
        if proxy:
            proxy_uri = self.build_uri(proxy)
            proxy = {
              'http': proxy_uri,
              'https': proxy_uri,
            }
            steam_client.session.proxies.update(proxy)
        captcha_gid, captcha_text = '-1', ''
        while True:
            try:
                resp = steam_client.login(login_name, password, None, email, email_passwd, captcha_gid, captcha_text)
                break
            except CaptchaRequired as err:
                if pass_login_captcha:
                    raise err
                captcha_gid = err
                captcha_id = self.generate_captcha(steam_client.session, captcha_gid, 'COMMUNITY')
                captcha_text = self.resolve_captcha(captcha_id)
                self.failed_captchas_counter += 1
                self.client.captchas_failed_stat.set("Капч не удалось решить: %d" % self.failed_captchas_counter)

        self.sucessfull_captchas_counter += 1
        self.client.captchas_resolved_stat.set("Капч решено успешно: %d" % self.sucessfull_captchas_counter)

        resp_message = resp.get('message', '')

        if 'name or password that you have entered is incorrect' in resp_message:
            raise SteamAuthError('Неверный логин или пароль: ' + login_name)

        if resp['requires_twofactor']:
            raise SteamAuthError('К аккаунту уже привязан Guard: ' + login_name)

        if resp.get('emailauth_needed', None):
            raise SteamAuthError('К аккаунту привязан Mail Guard. '
                                 'Почта и пароль от него не предоставлены')

        return steam_client

    def mobile_login(self, login_name, password, proxy=None, email=None, email_passwd=None, pass_login_captcha=False):
        steam_client = SteamClient()
        if proxy:
            proxy_uri = self.build_uri(proxy)
            proxy = {
              'http': proxy_uri,
              'https': proxy_uri,
            }
            steam_client.session.proxies.update(proxy)
        captcha_gid, captcha_text = '-1', ''
        while True:
            try:
                resp = steam_client.mobile_login(login_name, password, None, email, email_passwd, captcha_gid,
                                                 captcha_text)
                break
            except CaptchaRequired as err:
                if pass_login_captcha:
                    raise err
                captcha_gid = err
                captcha_id = self.generate_captcha(steam_client.session, captcha_gid, 'COMMUNITY')
                captcha_text = self.resolve_captcha(captcha_id)

        resp_message = resp.get('message', '')

        if 'name or password that you have entered is incorrect' in resp_message:
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

        steam_client.session.get("https://store.steampowered.com")  # get store cookies

        return steam_client

    def validate_phone(self, steam_client, phone_num):
        sessionid = steam_client.session.cookies.get(
            'sessionid', domain='store.steampowered.com')
        url = "https://store.steampowered.com/phone/validate"
        data = {"sessionID": sessionid, "phoneNumber": phone_num}
        response = self.request_post(steam_client.session,
                                     url, data=data)
        if not response.get("is_valid", True):
            raise AddPhoneError

    def addphone_request(self, steam_client, phone_num):
        sessionid = steam_client.session.cookies.get(
                    'sessionid', domain='steamcommunity.com')
        data = {
            'op': 'add_phone_number',
            'arg': phone_num,
            'sessionid': sessionid
        }
        response = self.request_post(steam_client.session,
                                     'https://steamcommunity.com/steamguard/phoneajax', data=data)
        logger.info(response)
        return response["success"]

    def fetch_email_code(self, email, email_password, steam_client):
        server = self.authorize_email(email, email_password)
        attempts = 0
        success = False
        while attempts < 5:
            attempts += 1
            result, data = server.uid("search", None, 'ALL')
            uid = data[0].split()[-1]
            result, data = server.uid("fetch", uid, '(UID BODY[TEXT])')
            try:
                mail = data[0][1].decode('utf-8')
                link = re.search(r'https://.+ConfirmEmailForAdd.+?(?:")', mail).group()
                link = link.rstrip('"')
                steam_client.session.get(link)
                success = True
                break
            except AttributeError:
                time.sleep(5)
                continue
            time.sleep(5)
        server.close()
        return success

    def email_confirmation(self, steam_client):
        sessionid = steam_client.session.cookies.get(
            'sessionid', domain='steamcommunity.com')
        data = {
            'op': 'email_confirmation',
            'arg': None,
            'sessionid': sessionid
        }
        response = self.request_post(steam_client.session,
                                     'https://steamcommunity.com/steamguard/phoneajax', data=data)
        return response["success"]

    def is_phone_attached(self, steam_client):
        sessionid = steam_client.session.cookies.get(
                    'sessionid', domain='steamcommunity.com')
        data = {
            'op': 'has_phone',
            'arg': None,
            'sessionid': sessionid
        }
        response = self.request_post(steam_client.session,
                                     'https://steamcommunity.com/steamguard/phoneajax', data=data)

        return response['has_phone']

    def checksms_request(self, steam_client, sms_code):
        sessionid = steam_client.session.cookies.get(
                    'sessionid', domain='steamcommunity.com')
        data = {
            'op': 'check_sms_code',
            'arg': sms_code,
            'sessionid': sessionid
        }
        response = self.request_post(
            steam_client.session, 'https://steamcommunity.com/steamguard/phoneajax', data=data)
        logger.info(response)
        return response["success"]

    def add_authenticator_request(self, steam_client):
        device_id = guard.generate_device_id(steam_client.oauth['steamid'])
        while True:
            try:
                mobguard_data = self.request_post(steam_client.session,
                    'https://api.steampowered.com/ITwoFactorService/AddAuthenticator/v0001/',
                    data = {
                        "access_token": steam_client.oauth['oauth_token'],
                        "steamid": steam_client.oauth['steamid'],
                        "authenticator_type": 1,
                        "device_identifier": device_id,
                        "sms_phone_id": 1
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
            try:
                mobguard_data['Session'][mafile_key] = steam_client.session.cookies.get(
                    "sessionid", domain="steamcommunity.com")
            except KeyError:
                mobguard_data['Session'][mafile_key] = ''

        return mobguard_data

    def finalize_authenticator_request(self, steam_client, mobguard_data, sms_code):
        one_time_code = guard.generate_one_time_code(mobguard_data['shared_secret'], int(time.time()))
        data = {
            "steamid": steam_client.oauth['steamid'],
            "activation_code": sms_code,
            "access_token": steam_client.oauth['oauth_token'],
            'authenticator_time': int(time.time()),
            'authenticator_code': one_time_code
        }
        while True:
            try:
                fin_resp = self.request_post(
                    steam_client.session,
                    'https://api.steampowered.com/ITwoFactorService/FinalizeAddAuthenticator/v0001/',
                    data=data, headers={'User-Agent': 'Steam App / Android / 2.3.11 / 5379038'})['response']
            except json.decoder.JSONDecodeError:
                logger.error("json error in the FinalizeAddAuthenticator request")
                time.sleep(3)
                continue
            logger.info(str(fin_resp))
            if fin_resp['status'] not in (1, 2):
                time.sleep(5)
                continue
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

    def create_account_web(self, email_name, email_password, login=None, password=None, proxy=None):
        session = requests.Session()
        if proxy:
            proxy_uri = self.build_uri(proxy)
            proxy = {
              'http': proxy_uri,
              'https': proxy_uri,
            }
            session.proxies.update(proxy)
        session.headers.update({'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36'),
                                'Accept-Language': 'q=0.8,en-US;q=0.6,en;q=0.4'})
        if login is None:
            login_name = self.generate_login_name()
        if password is None:
            password = self.generate_password()
        while True:
            Email = collections.namedtuple("Email", "name password generated_name")
            email_generated_name = email_name
            if self.client.generate_emails.get():
                domain = email_name.partition("@")[2]
                email_generated_name = login_name + "@" + domain
            email = Email(email_name, email_password, email_generated_name)
            logger.info("Using email: %s" % email.generated_name)

            while True:
                response = self.request_get(session, 'https://store.steampowered.com/join/refreshcaptcha/?count=1',
                                            headers={'Host': 'store.steampowered.com'},
                                            timeout=30, is_json=True)
                gid, sitekey = response['gid'], response['sitekey']
                captcha_id = self.captcha_service.generate_recaptcha(sitekey)
                captcha_text = self.resolve_captcha(captcha_id)
                if not captcha_text:
                    continue
                break
            logger.info("Confirming email... %s", login_name)
            try:
                creationid = self.confirm_email(session, gid, captcha_text, email)
                break
            except (InvalidEmail, imaplib.IMAP4.error) as err:
                self.client.add_log("Ошибка почты %s: %s" % (email.generated_name, err))
                continue

        logger.info("Email confirmed: %s %s", email.generated_name, login_name)

        data = {
            'accountname': login_name,
            'password': password,
            'count': '32',
            'lt': '0',
            'creation_sessionid': creationid
        }
        resp = self.request_post(session, 'https://store.steampowered.com/join/createaccount/',
                                 data=data, timeout=25)
        logger.info('create account response: %s', resp)

        return login_name, password, email.generated_name, email.password

    def resolve_captcha(self, captcha_id):
        result = self.captcha_service.resolve_captcha(captcha_id)
        logger.info("Resolved captcha: %s", result)
        if result is None:
            return result
        try:
            status, token, price = result
        except ValueError:
            status, token = result
            price = 0

        self.captchas_expenses_total += float(price)
        self.client.captchas_expenses_stat.set("Потрачено на капчи: %d" % self.captchas_expenses_total)
        return token

    def confirm_email(self, session, gid, captcha_text, email):
        data = {
            'captcha_text': captcha_text,
            'captchagid': gid,
            'email': email.generated_name
        }
        resp = self.request_post(session, 'https://store.steampowered.com/join/ajaxverifyemail', data=data)
        logger.info('ajaxverify response: %s', resp)
        if resp['success'] == 17:
            raise InvalidEmail("Данный почтовый адрес не поддерживается Steam")
        if resp['success'] != 1:
            raise LimitReached

        creationid = resp['sessionid']
        time.sleep(10)  # wait some time until email has been received
        link = self.fetch_confirmation_link(email.name, email.password, creationid)
        session.get(link)
        return creationid

    def generate_login_name(self):
        login_template = self.client.login_template.get()
        while True:
            if login_template:
                if self.counters_db["login_counters"].get(login_template, None) is None:
                    self.counters_db["login_counters"][login_template] = 0
                self.counters_db["login_counters"][login_template] += 1
                login_name = login_template.format(num=self.counters_db["login_counters"][login_template])
            else:
                login_name = self.generate_credential(2, 4, uppercase=False)
            r = self.request_post(requests.Session(), 'https://store.steampowered.com/join/checkavail',
                                  data={'accountname': login_name, 'count': 1})
            logger.info(str(r) + " %s", login_name)
            if r['bAvailable']:
                return login_name
            self.client.add_log("Логин %s занят" % login_name)
            time.sleep(3)

    @staticmethod
    def build_uri(proxy):
        if not proxy:
            return None
        protocols = {"SOCKS5", "SOCKS4", "HTTPS", "HTTP"}
        for protocol in protocols:
            if protocol in proxy.types:
                break
        uri = "%s://" % protocol.lower()
        if proxy.login and proxy.password:
            uri += "%s:%s@" % (proxy.login, proxy.password)
        uri += "%s:%s" % (proxy.host, proxy.port)
        return uri

    def check_proxy_ban(self, proxy):
        try:
            self.login("asd", "bkb", proxy=proxy, pass_login_captcha=True)
        except CaptchaRequired:
            return True
        except AuthException:
            raise ConnectionError
        except Exception:
            pass
        return False

    @staticmethod
    def generate_credential(start, end, uppercase=True):
        char_sets = [string.ascii_lowercase, string.digits, string.ascii_uppercase]
        random.shuffle(char_sets)
        func = lambda x: ''.join((random.choice(x) for _ in range(random.randint(start, end))))
        credential = ''.join(map(func, char_sets))
        if not uppercase:
            credential = credential.lower()
        return credential

    def generate_captcha(self, session, gid, domain):
        if domain == "STORE":
            url = 'https://store.steampowered.com/login/rendercaptcha/?gid={}'
        elif domain == "COMMUNITY":
            url = 'https://steamcommunity.com/login/rendercaptcha/?gid={}'
        else:
            raise Exception("WRONG domain")
        captcha_img = self.request_get(session, url.format(gid), timeout=30).content
        captcha_id = self.captcha_service.generate_captcha_img(captcha_img)
        return captcha_id

    def activate_account(self, steam_client, summary, real_name, country):
        nickname = self.generate_credential(2, 4, uppercase=False)
        nickname_template = self.client.nickname_template.get()
        if nickname_template:
            if "{login}" in nickname_template:
                nickname = steam_client.login_name
            else:
                if self.counters_db["nickname_counters"].get(nickname_template, None) is None:
                    self.counters_db["nickname_counters"][nickname_template] = 0
                self.counters_db["nickname_counters"][nickname_template] += 1
                nickname = self.client.nickname_template.get().format(num=self.counters_db["nickname_counters"][nickname_template])
        url = 'https://steamcommunity.com/profiles/{}/edit'.format(steam_client.steamid)
        data = {
            'sessionID': steam_client.get_session_id(),
            'type': 'profileSave',
            'personaName': nickname,
            'summary': summary,
            'real_name': real_name,
            'country': country
        }
        steam_client.session.post(url, data=data, timeout=30, attempts=3)

    @staticmethod
    def upload_avatar(steam_client, avatar):
        data = {
            "MAX_FILE_SIZE": 1048576,
            "type": "player_avatar_image",
            "sId": steam_client.steamid,
            "sessionid": steam_client.get_session_id(),
            "doSub": 1,
            "json": 1
        }
        steam_client.session.post("https://steamcommunity.com/actions/FileUploader", files={"avatar": avatar}, data=data)

    @staticmethod
    def edit_profile(steam_client):
        data = dict(sessionid=(None, steam_client.get_session_id()),
                    Privacy=(None, json.dumps({"PrivacyProfile": 3, "PrivacyInventory": 3,
                                               "PrivacyInventoryGifts": 3, "PrivacyOwnedGames": 3,
                                               "PrivacyPlaytime": 3})),
                    eCommentPermission=(None, '1')
                    )

        success = 0
        while True:
            resp = steam_client.session.post(
                "https://steamcommunity.com/profiles/%s/ajaxsetprivacy/" % steam_client.steamid, files=data,
                headers={"Referer": "https://steamcommunity.com/profiles/%s/edit/settings/" % steam_client.steamid},
                timeout=10, attempts=3)
            try:
                success = resp.json()["success"]
            except AttributeError as err:
                logging.error("Edit profile error %s: %s", steam_client.login_name, err)
                time.sleep(30)
            except (json.decoder.JSONDecodeError, KeyError) as err:
                logging.error("%s: %s", err, resp.text)
                time.sleep(5)

            if success:
                logging.info("Successfully edited profile")
                return

    @staticmethod
    def fetch_tradeoffer_link(steam_client):
        url = 'http://steamcommunity.com/profiles/%s/tradeoffers/privacy' % steam_client.steamid
        resp = steam_client.session.get(url, timeout=30)
        regexr = r'https:\/\/steamcommunity.com\/tradeoffer\/new\/\?partner=.+&token=.+(?=" )'
        try:
            return re.search(regexr, resp.text).group()
        except AttributeError as err:
            logger.error("Failed to fetch offer link %s", err)
            return ''

    def generate_password(self):
        passwd_template = self.client.passwd_template.get()
        while True:
            if passwd_template:
                if self.counters_db["password_counters"].get(passwd_template, None) is None:
                    self.counters_db["password_counters"][passwd_template] = 0
                self.counters_db["password_counters"][passwd_template] += 1
                password = passwd_template.format(num=self.counters_db["password_counters"][passwd_template])
            else:
                password = self.generate_credential(4, 6, uppercase=False)
            r = self.request_post(requests.Session(), 'https://store.steampowered.com/join/checkpasswordavail/',
                                  data={'accountname': '', 'count': 1, 'password': password})
            logger.info(str(r) + " %s", password)
            if r['bAvailable']:
                return password
            time.sleep(3)
            self.client.add_log("Пароль %s слишком часто используется и поэтому не был принят" % password)

    def fetch_confirmation_link(self, email, email_password, creationid):
        server = self.authorize_email(email, email_password)
        attempts = 0
        while attempts < 5:
            attempts += 1
            result, data = server.uid("search", None, 'ALL')
            uid = data[0].split()[-1]
            result, data = server.uid("fetch", uid, '(UID BODY[TEXT])')
            try:
                mail = data[0][1].decode('utf-8')
                link = re.search(r'(https://.+newaccountverification.+?)\r', mail).group(1)
            except AttributeError:
                time.sleep(5)
                continue
            creationid_from_link = re.search(r"creationid=(\w+)", link).group(1)
            if creationid == creationid_from_link:
                server.close()
                return link
            time.sleep(5)
        server.close()
        raise InvalidEmail("Не удается получить письмо от Steam")

    def authorize_email(self, email, email_password):
        email_domain = email.partition("@")[2]
        imap_host = convert_edomain_to_imap(email_domain, self.client.imap_hosts)

        if imap_host is None:
            raise InvalidEmail("Не удается найти imap host для данного email домена: %s" % email_domain)
        server = imaplib.IMAP4_SSL(imap_host)
        server.login(email, email_password)
        server.select()
        return server

    @staticmethod
    def select_profile_data(data, type):
        result = ""
        if data:
            if type == SelectionType.RANDOM:
                result = random.choice(data)
            elif type == SelectionType.CONSISTENT:
                result = data.pop(0)
                data.append(result)

        return result


class RuCaptcha:

    def __init__(self, api_key, host):
        if not host:
            host = "rucaptcha.com"
        else:
            host = re.search(r"(?:https?://)?(.+)/?", host).group(1).rstrip("/")
        host = "http://" + host + "/%s"
        self.host = host
        self.api_key = api_key

    def get_balance(self):
        resp = requests.post(self.host % 'res.php',
                             data={'key': self.api_key,
                                   'action': 'getbalance'})
        logger.info(resp.text)
        if 'ERROR_ZERO_BALANCE' in resp.text:
            raise RuCaptchaError('На счету нулевой баланс')
        elif 'ERROR_WRONG_USER_KEY' in resp.text or 'ERROR_KEY_DOES_NOT_EXIST' in resp.text:
            raise RuCaptchaError('Неправильно введен API ключ')

        return resp.text

    def generate_captcha_img(self, captcha_img):
        resp = requests.post(self.host % 'in.php',
                             files={'file': ('captcha', captcha_img, 'image/png')},
                             data={'key': self.api_key},
                             timeout=30)

        captcha_id = resp.text.partition('|')[2]
        return captcha_id

    def generate_recaptcha(self, sitekey):
        resp = requests.post(self.host % 'in.php',
                             data={'key': self.api_key, 'method': 'userrecaptcha', 'googlekey': sitekey,
                                   'pageurl': 'https://store.steampowered.com/join/refreshcaptcha/?count=1'},
                             timeout=30)
        captcha_id = resp.text.partition('|')[2]
        return captcha_id

    def resolve_captcha(self, captcha_id):
        while True:
            time.sleep(5)
            r = requests.post(self.host % 'res.php' + '?key={}&action=get2&id={}'
                              .format(self.api_key, captcha_id), timeout=30)
            logger.info(r.text)
            if 'CAPCHA_NOT_READY' in r.text:
                continue
            elif 'ERROR_CAPTCHA_UNSOLVABLE' in r.text:
                return None
            break

        return r.text.split('|')

    def report_bad(self, captcha_id):
        requests.post(self.host % 'res.php' + '?key={}&action=reportbad&id={}'
                      .format(self.api_key, captcha_id), timeout=30)


class AntiCaptcha(AnticaptchaClient):

    def __init__(self, api_key, host):
        if not host:
            host = "api.anti-captcha.com"
        else:
            host = re.search(r"(?:https?://)?(.+)/?", host).group(1).rstrip("/")
        super().__init__(api_key, host=host)

    def get_balance(self):
        return self.getBalance()

    def generate_captcha_img(self, captcha_img):
        task = ImageToTextTask(io.BytesIO(captcha_img))
        job = self.createTask(task)
        return job

    def generate_recaptcha(self, sitekey):
        task = NoCaptchaTaskProxylessTask("https://store.steampowered.com/join/refreshcaptcha/?count=1",
                                          sitekey)
        job = self.createTask(task)
        return job

    @staticmethod
    def resolve_captcha(job):
        job.join()
        status, price = job._last_result["status"], job._last_result["cost"]
        try:
            solution = job.get_solution_response()  # ReCaptcha
        except KeyError:
            solution = job.get_captcha_text()
        return status, solution, price

    def report_bad(self, job):
        self.reportIncorrectImage(job.task_id)


if __name__ == '__main__':
    reg = SteamRegger(None)
