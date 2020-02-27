import enum
import time
import re
import json
import logging
import collections
from typing import List

import requests
from bs4 import BeautifulSoup
from steampy import guard
from steampy.confirmation import ConfirmationExecutor
from steampy.login import LoginExecutor, InvalidCredentials
from steampy.utils import text_between, merge_items_with_descriptions_from_inventory, GameOptions, \
    steam_id_to_account_id, merge_items_with_descriptions_from_offers, get_description_key, \
    merge_items_with_descriptions_from_offer, account_id_to_steam_id

logger = logging.getLogger('__main__')

class Currency(enum.IntEnum):
    USD = 1
    GBP = 2
    EURO = 3
    CHF = 4


class Asset:
    def __init__(self, asset_id: str, game: GameOptions, amount: int = 1) -> None:
        self.asset_id = asset_id
        self.game = game
        self.amount = amount

    def to_dict(self):
        return {
            'appid': int(self.game.app_id),
            'contextid': self.game.context_id,
            'amount': self.amount,
            'assetid': self.asset_id
        }


class TradeOfferState(enum.IntEnum):
    Invalid = 1
    Active = 2
    Accepted = 3
    Countered = 4
    Expired = 5
    Canceled = 6
    Declined = 7
    InvalidItems = 8
    ConfirmationNeed = 9
    CanceledBySecondaryFactor = 10
    StateInEscrow = 11


def login_required(func):
    def func_wrapper(self, *args, **kwargs):
        if not self.isLoggedIn:
            raise LoginRequired('Use login method first')
        else:
            return func(self, *args, **kwargs)

    return func_wrapper

class LoginRequired(Exception):
    pass

class SteamClient:
    API_URL = "https://api.steampowered.com"
    COMMUNITY_URL = "https://steamcommunity.com"
    BROWSER_HEADERS = {
            'User-Agent': ('Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) '
                           'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Mobile Safari/537.36'),
            'Accept-Language': 'q=0.8,en-US;q=0.6,en;q=0.4'}
    MARKET_CURRENCIES = {'kr': 'Norwegian Krone', 'pуб.': 'Russian Ruble'}

    def __init__(self, api_key=None, proxy=None):
        self._api_key = api_key
        self._session = requests.Session()
        self.isLoggedIn = False
        self.mafile = None
        self.login_name = None
        self.password = None
        self.oauth = None
        self.steamid = None

    @property
    def session(self):
        return self._session

    def _fetch_shared_secret(self, mafile):
        shared_secret = None
        if mafile is not None:
            if isinstance(mafile, str):  # if json
                self.mafile = guard.load_steam_guard(mafile)
            else:
                self.mafile = mafile
            shared_secret = self.mafile['shared_secret']
        return shared_secret

    def login(self, username: str, password: str, mafile=None,
              email=None, email_passwd=None, captcha_gid='-1', captcha_text='') -> None:
        shared_secret = self._fetch_shared_secret(mafile)
        self._session.headers.update(self.BROWSER_HEADERS)
        login_response = LoginExecutor(username, password, shared_secret,
                                       self._session, email, email_passwd, captcha_gid, captcha_text).login()
        try:
            self.steamid = login_response['transfer_parameters']['steamid']
        except KeyError as err:
            logger.info("%s: %s", err, login_response)
        # get steamcommunity cookies
        # self._session.get('https://steamcommunity.com/market/')

        # set english language
        self._session.post('https://steamcommunity.com/actions/SetLanguage/',
                           data={'language': 'english',
                                 'sessionid': self.get_session_id()})

        self.isLoggedIn = True
        self.login_name = username
        self.password = password

        return login_response

    def mobile_login(self, username, password, mafile=None,
                     email=None, email_passwd=None, captcha_gid='-1', captcha_text=''):
        shared_secret = self._fetch_shared_secret(mafile)
        self._session.headers.update(self.BROWSER_HEADERS)
        self._session.cookies.set('mobileClientVersion', '0 (2.1.3)')
        self._session.cookies.set('Steam_Language', 'english')
        self._session.cookies.set('mobileClient', 'android')
        login_response = LoginExecutor(username, password, shared_secret,
                                       self._session, email, email_passwd, captcha_gid, captcha_text).mobile_login()
        oauth = login_response.get('oauth', None)
        if oauth:
            self.oauth = json.loads(oauth)
            self.steamid = self.oauth['steamid']

        # get steamcommunity cookies
        # self._session.get('http://steamcommunity.com/market/')

        # set english language
        del self._session.cookies['Steam_Language']
        self._session.post('https://steamcommunity.com/actions/SetLanguage/',
                           data={'language': 'english',
                                 'sessionid': self.get_session_id()})

        self.isLoggedIn = True
        self.login_name = username
        self.password = password

        return login_response

    @login_required
    def logout(self) -> None:
        url = LoginExecutor.STORE_URL + '/logout/'
        params = {'sessionid': self.get_session_id()}
        self._session.post(url, params)
        if self.is_session_alive():
            raise Exception("Logout unsuccessful")
        self.was_login_executed = False

    @login_required
    def is_session_alive(self):
        steam_login = self.username
        main_page_response = self._session.get(self.COMMUNITY_URL)
        return steam_login in main_page_response.text

    def api_call(self, request_method: str, interface: str, api_method: str, version: str,
                 params: dict = None) -> requests.Response:
        url = '/'.join([self.API_URL, interface, api_method, version])
        attempts = 0
        response = None
        while attempts < 3:
            try:
                if request_method == 'GET':
                    response = requests.get(url, params=params, timeout=60).json()
                else:
                    response = requests.post(url, data=params, timeout=60).json()
                break
            except json.decoder.JSONDecodeError as err:
                print(err)
            attempts += 1
        if not response:
            raise Exception('The API server is unreachable')
        if self.is_invalid_api_key(response):
            raise InvalidCredentials('Invalid API key')
        return response

    @staticmethod
    def is_invalid_api_key(response: requests.Response) -> bool:
        msg = 'Access is denied. Retrying will not help. Please verify your <pre>key=</pre> parameter'
        return msg in str(response)

    @login_required
    def get_my_inventory(self, game: GameOptions, merge: bool = True) -> dict:
        url = self.COMMUNITY_URL + '/my/inventory/json/' + \
              game.app_id + '/' + \
              game.context_id
        result = {}
        start = 0
        more = True
        while more:
            try:
                response_dict = self._session.get(url, params={'start': start}, timeout=60).json()
                if not response_dict['success']:
                    logger.info("No items found for appid %s: %s", game.app_id, response_dict)
                    return result
                more = response_dict['more']
                if merge:
                    result.update(merge_items_with_descriptions_from_inventory(response_dict, game))
                else:
                    result.update(response_dict['rgInventory'])
            except (json.decoder.JSONDecodeError, KeyError, TypeError) as err:
                logger.error('%s error while getting my inventory', err)
                time.sleep(5)
                continue

            start += 2000

        return result

    @login_required
    def get_partner_inventory(self, partner_steam_id: str, game: GameOptions, merge: bool = True) -> dict:
        params = {'sessionid': self.get_session_id(),
                  'partner': partner_steam_id,
                  'appid': int(game.app_id),
                  'contextid': game.context_id}
        partner_account_id = steam_id_to_account_id(partner_steam_id)
        headers = {'X-Requested-With': 'XMLHttpRequest',
                   'Referer': self.COMMUNITY_URL + '/tradeoffer/new/?partner=' + partner_account_id,
                   'X-Prototype-Version': '1.7'}
        response_dict = self._session.get(self.COMMUNITY_URL + '/tradeoffer/new/partnerinventory/',
                                          params=params,
                                          headers=headers).json()
        if merge:
            return merge_items_with_descriptions_from_inventory(response_dict, game)
        return response_dict

    def get_session_id(self) -> str:
        return self._session.cookies.get('sessionid', domain='steamcommunity.com')

    def get_trade_offers_summary(self) -> dict:
        params = {'key': self._api_key}
        return self.api_call('GET', 'IEconService', 'GetTradeOffersSummary', 'v1', params)

    def get_trade_offers(self, merge, get_descriptions=1):
        params = {'key': self._api_key,
                  'get_sent_offers': 1,
                  'get_received_offers': 1,
                  'get_descriptions': get_descriptions,
                  'language': 'english',
                  'active_only': 1,
                  'historical_only': 0,
                  'time_historical_cutoff': ''}
        response = self.api_call('GET', 'IEconService', 'GetTradeOffers', 'v1', params)
        response = self._filter_non_active_offers(response)
        if merge:
            response = merge_items_with_descriptions_from_offers(response)
        return response

    @staticmethod
    def _filter_non_active_offers(offers_response):
        offers_received = offers_response['response'].get('trade_offers_received', [])
        offers_sent = offers_response['response'].get('trade_offers_sent', [])
        offers_response['response']['trade_offers_received'] = list(
            filter(lambda offer: offer['trade_offer_state'] == TradeOfferState.Active, offers_received))
        offers_response['response']['trade_offers_sent'] = list(
            filter(lambda offer: offer['trade_offer_state'] == TradeOfferState.Active, offers_sent))
        return offers_response

    def get_trade_offer(self, trade_offer_id: str, merge: bool = True) -> dict:
        params = {'key': self._api_key,
                  'tradeofferid': trade_offer_id,
                  'language': 'english'}
        response = self.api_call('GET', 'IEconService', 'GetTradeOffer', 'v1', params)
        if merge:
            descriptions = {get_description_key(offer): offer for offer in response['response']['descriptions']}
            offer = response['response']['offer']
            response['response']['offer'] = merge_items_with_descriptions_from_offer(offer, descriptions)
        return response

    @login_required
    def accept_trade_offer(self, trade_offer_id: str, partner: str) -> dict:
        session_id = self.get_session_id()
        accept_url = self.COMMUNITY_URL + '/tradeoffer/' + trade_offer_id + '/accept'
        params = {'sessionid': session_id,
                  'tradeofferid': trade_offer_id,
                  'serverid': '1',
                  'partner': partner,
                  'captcha': ''}
        headers = {'Referer': self._get_trade_offer_url(trade_offer_id)}
        response = None
        try:
            response = self._session.post(accept_url, data=params, headers=headers, timeout=60).json()
            if response.get('needs_mobile_confirmation', False):
                return self._confirm_transaction(trade_offer_id)
        except (AttributeError, json.decoder.JSONDecodeError) as err:
            logger.error("%s %s", err, accept_url)
            return None

        return response

    def _fetch_trade_partner_id(self, trade_offer_id: str, my_steamid: str) -> str:
        # этот метод на данный момент неактуален
        url = self._get_trade_offer_url(trade_offer_id)
        url = 'http://steamcommunity.com/profiles/{}/tradeoffers/'.format(my_steamid)
        while True:
            try:
                offer_response_text = self._session.get(url, timeout=60).text
                break
            except requests.exceptions.ProxyError as err:
                print(err)
                time.sleep(3)
                continue
        s = BeautifulSoup(offer_response_text, 'html.parser')
        tradeoffer_element = s.find(id='tradeofferid_' + trade_offer_id)
        partner_id = tradeoffer_element.find(class_='playerAvatar online')['data-miniprofile']
        return partner_id
        if 'You have logged in from a new device. In order to protect the items' in offer_response_text:
            raise SevenDaysHoldException("Account has logged in a new device and can't trade for 7 days")
        return text_between(offer_response_text, "var g_ulTradePartnerSteamID = '", "';")

    def _get_trade_offer_url(self, trade_offer_id: str) -> str:
        return self.COMMUNITY_URL + '/tradeoffer/' + trade_offer_id

    def _confirm_transaction(self, trade_offer_id: str) -> dict:
        confirmation_executor = ConfirmationExecutor(trade_offer_id,
                                                     self.mafile['identity_secret'],
                                                     str(self.mafile['Session']['SteamID']),
                                                     self._session)
        return confirmation_executor.send_trade_allow_request()

    def confirm_transactions(self):
        confirmation_executor = ConfirmationExecutor('', self.mafile['identity_secret'],
                                                     str(self.mafile['Session']['SteamID']),
                                                     self._session)
        return confirmation_executor.send_markettrans_allow_request()

    def decline_trade_offer(self, trade_offer_id: str) -> dict:
        params = {'key': self._api_key,
                  'tradeofferid': trade_offer_id}
        return self.api_call('POST', 'IEconService', 'DeclineTradeOffer', 'v1', params)

    def cancel_trade_offer(self, trade_offer_id: str) -> dict:
        params = {'key': self._api_key,
                  'tradeofferid': trade_offer_id}
        return self.api_call('POST', 'IEconService', 'CancelTradeOffer', 'v1', params)

    @login_required
    def make_offer(self, token: str, items_from_me: List[Asset], items_from_them: List[Asset], partner_steam_id: str,
                   message: str = '') -> dict:
        offer = {
            'newversion': True,
            'version': 4,
            'me': {
                'assets': [asset.to_dict() for asset in items_from_me],
                'currency': [],
                'ready': False
            },
            'them': {
                'assets': [asset.to_dict() for asset in items_from_them],
                'currency': [],
                'ready': False
            }
        }

        session_id = self.get_session_id()
        url = self.COMMUNITY_URL + '/tradeoffer/new/send'
        server_id = 1
        params = {
            'sessionid': session_id,
            'serverid': server_id,
            'partner': partner_steam_id,
            'tradeoffermessage': message,
            'json_tradeoffer': json.dumps(offer),
            'captcha': '',
            'trade_offer_create_params': json.dumps({"trade_offer_access_token": token})
        }
        partner_account_id = steam_id_to_account_id(partner_steam_id)
        headers = {'Referer': self.COMMUNITY_URL + '/tradeoffer/new/?partner=' + partner_account_id + '&token=' + token,
                   'Origin': self.COMMUNITY_URL}
        while True:
            try:
                response = self._session.post(url, data=params, headers=headers, timeout=60).json()
                break
            except json.decoder.JSONDecodeError as err:
                logger.error("%s %s", err, url)
                time.sleep(3)

        if response.get('needs_mobile_confirmation'):
            response = self._confirm_transaction(response['tradeofferid'])
        return response

    def fetch_price(self, item_hash_name: str, game: GameOptions, currency: str = Currency.USD) -> dict:
        url = self.COMMUNITY_URL + '/market/priceoverview/'
        params = {'country': 'PL',
                  'currency': currency,
                  'appid': game.app_id,
                  'market_hash_name': item_hash_name}
        return self._session.get(url, params=params, timeout=60).json()

    def create_market_listing(self, assetid, price, appid, context_id=2):
        def send_marketform():
            sessionid = self._session.cookies.get('sessionid', domain='store.steampowered.com')
            data = {
                'sessionid': sessionid,
                'full_name': self.login_name,
                'permanent_address1': 'City',
                'permanent_state': '',
                'permanent_address2': '',
                'permanent_postalcode': '',
                'mailing_address1': '',
                'mailing_address2': '',
                'mailing_city': '',
                'mailing_state': '',
                'mailing_postalcode': '',
                'permanent_city': 'City',
                'permanent_country': 'RU',
                'mailing_state_select': 'AE',
                'mailing_country': 'RU',
                'full_name_signed': self.login_name
            }
            headers = {
                'Host': 'store.steampowered.com',
                'Origin': 'https://store.steampowered.com',
                'Referer': 'https://store.steampowered.com/account/forms/6050w/'
            }
            self._session.get('https://store.steampowered.com/account/forms/6050w/')
            self._session.post('https://store.steampowered.com/account/forms/submit_6050w_non_us/',
                                    data=data, headers=headers)
            print('marketform sent')


        sessionid = self.get_session_id()
        headers = {
            'Origin': 'https://steamcommunity.com',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Referer': 'https://steamcommunity.com/my/inventory/',
            'Accept-Encoding': 'gzip, deflate',
            "X-Requested-With": "XMLHttpRequest"
        }
        payload = {
            'sessionid': sessionid,
            'appid': appid,
            'contextid': context_id,
            'assetid': assetid,
            'amount': 1,
            'price': price
        }

        while True:
            try:
                response = self._session.post('https://steamcommunity.com/market/sellitem/',
                                              data=payload, headers=headers, timeout=10).json()
            except json.decoder.JSONDecodeError as err:
                logger.error('json decode error while putting item on sale: %s', err)
                continue
            error_msg = response.get('message', None)
            if error_msg:
                logger.error(str(error_msg))
                if 'You are not allowed to sell more than 200 items' in error_msg:
                    send_marketform()
                    time.sleep(900)
                    continue
                elif 'We were unable to contact' in error_msg:
                    continue
            break

        return response

class SevenDaysHoldException(Exception):
    pass
