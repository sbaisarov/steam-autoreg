import enum
import time
import logging
from typing import List

import requests
from bs4 import BeautifulSoup

from steampy import guard
from steampy.login import InvalidCredentials


class Confirmation:
    def __init__(self, _id, data_confid, data_key):
        self.id = _id.split('conf')[1]
        self.data_confid = data_confid
        self.data_key = data_key


class Tag(enum.Enum):
    CONF = 'conf'
    DETAILS = 'details'
    ALLOW = 'allow'
    CANCEL = 'cancel'


class ConfirmationExecutor:
    CONF_URL = "https://steamcommunity.com/mobileconf"

    def __init__(self, trade_offer_id: str, identity_secret: str, my_steam_id: str, session: requests.Session) -> None:
        self._trade_offer_id = trade_offer_id
        self._my_steam_id = my_steam_id
        self._identity_secret = identity_secret
        self._session = session
        self._session.headers.update({'User-Agent': ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.24 '
                                      '(KHTML, like Gecko) Chrome/11.0.696.34 Safari/534.24')})

    def send_trade_allow_request(self) -> dict:
        confirmations = self._get_confirmations()
        confirmation = self._select_trade_offer_confirmation(confirmations)
        conf_status = self._confirm_trans(confirmation)
        return conf_status

    def send_markettrans_allow_request(self) -> dict:
        confirmations = self._get_confirmations()
        resp = self._multi_confimm_trans(confirmations)

    def _confirm_trans(self, confirmation):
        tag = Tag.ALLOW
        params = self._create_confirmation_params(tag.value)
        params['op'] = tag.value,
        params['cid'] = confirmation.data_confid
        params['ck'] = confirmation.data_key
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        resp = self._session.get(
            self.CONF_URL + '/ajaxop', params=params, headers=headers, timeout=60).json()
        return resp

    def _multi_confimm_trans(self, confirmations):
        tag = Tag.ALLOW
        params = self._create_confirmation_params(tag.value)
        params['op'] = tag.value,
        params_list = list(params.items())
        for conf in confirmations:
            params_list.append(('cid[]', conf.data_confid))
            params_list.append(('ck[]', conf.data_key))
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        resp = self._session.post(
            self.CONF_URL + '/multiajaxop', data=params_list, headers=headers, timeout=60)
        return resp

    def _get_confirmations(self) -> List[Confirmation]:
        confirmations = []
        confirmations_page = self._fetch_confirmations_page()
        soup = BeautifulSoup(confirmations_page.text, 'html.parser')
        if soup.select('#mobileconf_empty'):
            return confirmations
        for confirmation_div in soup.select('#mobileconf_list .mobileconf_list_entry'):
            _id = confirmation_div['id']
            data_confid = confirmation_div['data-confid']
            data_key = confirmation_div['data-key']
            confirmations.append(Confirmation(_id, data_confid, data_key))
        return confirmations

    def _fetch_confirmations_page(self) -> requests.Response:
        tag = Tag.CONF.value
        params = self._create_confirmation_params(tag)
        headers = {'X-Requested-With': 'com.valvesoftware.android.steam.community'}
        response = self._session.get(self.CONF_URL + '/conf', params=params, headers=headers, timeout=60)
        if 'Steam Guard Mobile Authenticator is providing incorrect Steam Guard codes.' in response.text:
            raise InvalidCredentials('Invalid Steam Guard file')
        elif "You've made too many requests recently." in response.text:
            print('too many attempts made recently, waiting for 10 minutes')
            time.sleep(600)
        return response

    def _fetch_confirmation_details_page(self, confirmation: Confirmation) -> str:
        tag = 'details' + confirmation.id
        params = self._create_confirmation_params(tag)
        response = self._session.get(self.CONF_URL + '/details/' + confirmation.id, params=params, timeout=60)
        return response.json()['html']

    def _create_confirmation_params(self, tag_string: str) -> dict:
        timestamp = int(time.time())
        confirmation_key = guard.generate_confirmation_key(self._identity_secret, tag_string, timestamp)
        android_id = guard.generate_device_id(self._my_steam_id)
        return {'p': android_id,
                'a': self._my_steam_id,
                'k': confirmation_key,
                't': timestamp,
                'm': 'android',
                'tag': tag_string}

    def _select_trade_offer_confirmation(self, confirmations: List[Confirmation]) -> Confirmation:
        for confirmation in confirmations:
            confirmation_details_page = self._fetch_confirmation_details_page(confirmation)
            confirmation_id = self._get_confirmation_trade_offer_id(confirmation_details_page)
            if confirmation_id == self._trade_offer_id:
                return confirmation
        raise ConfirmationExpected

    @staticmethod
    def _get_confirmation_trade_offer_id(confirmation_details_page: str) -> str:
        soup = BeautifulSoup(confirmation_details_page, 'html.parser')
        full_offer_id = soup.select('.tradeoffer')[0]['id']
        return full_offer_id.split('_')[1]


class ConfirmationExpected(Exception):
    pass
