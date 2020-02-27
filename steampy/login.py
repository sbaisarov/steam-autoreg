import base64
import time
import json

import requests
import rsa

from steampy import guard
from steampy.utils import convert_edomain_to_imap


class LoginExecutor:
    COMMUNITY_URL = "https://steamcommunity.com"
    STORE_URL = 'https://store.steampowered.com'
    API_URL = 'https://api.steampowered.com'

    def __init__(self, username, password, shared_secret, session,
                 email, email_passwd, captcha_gid='-1', captcha_text=''):
        self.username = username
        self.password = password
        self.email = email
        self.email_passwd = email_passwd
        self.captcha_gid = captcha_gid
        self.captcha_text = captcha_text
        self.shared_secret = shared_secret
        self.session = session

    def login(self) -> requests.Session:
        login_response = self._send_login_request()
        self._check_for_captcha(login_response)
        self._perform_redirects(login_response)
        return login_response

    def mobile_login(self):
        login_response = self._send_login_request(mobile_request=True)
        self._check_for_captcha(login_response)
        return login_response

    def _send_login_request(self, mobile_request=False):
        one_time_code = ''
        emailauth = ''
        second_attempt = False
        attempts = 0
        response = None
        while attempts < 3:
            attempts += 1
            rsa_params = self._fetch_rsa_params()
            encrypted_password = self._encrypt_password(rsa_params)
            rsa_timestamp = rsa_params['rsa_timestamp']
            if self.shared_secret:
                # resp = requests.post(self.API_URL + '/ITwoFactorService/QueryTime/v0001/',
                #                      data={'steamid': 0}).json()
                # print(resp)
                # timestamp = int(resp['response']['server_time'])
                timestamp = int(time.time())
                one_time_code = guard.generate_one_time_code(
                    self.shared_secret, timestamp)
            if mobile_request:
                request_data = self._prepare_mobile_login_request_data(encrypted_password, rsa_timestamp,
                                                                       one_time_code, emailauth)
            else:
                request_data = self._prepare_login_request_data(encrypted_password, rsa_timestamp,
                                                                one_time_code, emailauth)
            try:
                response = self.session.post(self.COMMUNITY_URL + '/login/dologin',
                                             data=request_data, attempts=3).json()
            except json.decoder.JSONDecodeError as err:
                print(err, '/login/dologin')
                continue

            if response is None:
                continue

            if len(response) == 3 and self.shared_secret and not second_attempt:
                time.sleep(30 - timestamp % 30)  # wait until the next code is generated
                second_attempt = True
                continue

            if response.get('emailauth_needed', None):
                if self.email and self.email_passwd:
                    imap_host = convert_edomain_to_imap(self.email, "../database/imap-hosts.json")
                    time.sleep(10)
                    emailauth = guard.fetch_emailauth(self.email, self.email_passwd, imap_host)
                    continue
            break

        if response is None:
            raise AuthException("Can't log in %s:%s" % (self.username, self.password))

        return response

    def _fetch_rsa_params(self) -> dict:
        while True:
            try:
                key_response = self.session.post(self.STORE_URL + '/login/getrsakey/',
                                                 data={'username': self.username}, attempts=3).json()
                rsa_mod = int(key_response['publickey_mod'], 16)
                break
            except (json.decoder.JSONDecodeError, KeyError) as err:
                print(err, '/login/getrsakey/')
                time.sleep(3)

        rsa_exp = int(key_response['publickey_exp'], 16)
        rsa_timestamp = key_response['timestamp']
        return {'rsa_key': rsa.key.PublicKey(rsa_mod, rsa_exp),
                'rsa_timestamp': rsa_timestamp}

    def _encrypt_password(self, rsa_params: dict) -> str:
        return base64.b64encode(
            rsa.pkcs1.encrypt(self.password.encode('utf-8'), rsa_params['rsa_key']))

    def _prepare_login_request_data(self, encrypted_password: str, rsa_timestamp: str,
                                    one_time_code: str, emailauth: str)-> dict:
        return {
            'password': encrypted_password,
            'username': self.username,
            'twofactorcode': one_time_code,
            'emailauth': emailauth,
            'loginfriendlyname': '',
            'captchagid': self.captcha_gid,
            'captcha_text': self.captcha_text,
            'emailsteamid': '',
            'rsatimestamp': rsa_timestamp,
            'remember_login': 'true',
            'donotcache': str(int(time.time() * 1000))
        }

    def _prepare_mobile_login_request_data(self, encrypted_password, rsa_timestamp,
                                           one_time_code, emailauth):
        return {
            'username': self.username,
            'password': encrypted_password,
            'twofactorcode': one_time_code,
            'captchagid': self.captcha_gid,
            'captcha_text': self.captcha_text,
            'emailsteamid': '',
            'emailauth': emailauth,
            'rsatimestamp': rsa_timestamp,
            'remember_login': 'false',
            'oauth_client_id': 'DE45CD61',
            'oauth_scope': 'read_profile write_profile read_client write_client',
            'loginfriendlyname': '#login_emailauth_friendlyname_mobile',
            'donotcache': str(int(time.time() * 1000))
        }

    @staticmethod
    def _check_for_captcha(login_response: dict) -> None:
        if login_response.get('captcha_needed', False):
            raise CaptchaRequired(login_response["captcha_gid"])

    @staticmethod
    def _assert_valid_credentials(login_response: requests.Response) -> None:
        if not login_response.json()['success']:
            raise InvalidCredentials(login_response.json()['message'])

    def _perform_redirects(self, response_dict: dict) -> requests.Response:
        try:
            parameters = response_dict['transfer_parameters']
        except KeyError:
            return
        for url in response_dict['transfer_urls']:
            self.session.post(url, parameters, attempts=3)

    def _fetch_home_page(self, session: requests.Session) -> requests.Response:
        return session.post(self.COMMUNITY_URL + '/my/home/', attempts=3)


class InvalidCredentials(Exception):
    pass


class CaptchaRequired(Exception):
    pass


class AuthException(Exception):
    pass