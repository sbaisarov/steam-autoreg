import requests
import re
import time
import json
import logging

class OnlineSimError(Exception): pass
class SmsActivateError(Exception): pass

logger = logging.getLogger()

class OnlineSimApi:

    def __init__(self, api_key):
        self.api_key = api_key
        self.used_codes = set()

    def request_new_number(self):
        url = 'http://onlinesim.ru/api/getNum.php'
        data = {'service': 'Steam', 'apikey': self.api_key, 'form': '1'}
        resp = self._send_request(url, data)
        while True:
            try:
                tzid = resp['tzid']
                break
            except KeyError:
                if 'TRY_AGAIN_LATER' in resp['response']:
                    print('TRY_AGAIN_LATER in response')
                    time.sleep(3)
                    continue
                raise OnlineSimError(resp['response'])
        return tzid

    def get_number(self, tzid):
        url = 'http://onlinesim.ru/api/getState.php'
        data = {'message_to_code': 1, 'tzid': tzid, 'apikey': self.api_key}
        resp = self._send_request(url, data)
        try:
            number = resp[0]['number']
        except (KeyError, IndexError):
            raise OnlineSimError(resp['response'])
        return number

    def get_sms_code(self, tzid, is_repeated=False):
        attempts = 0
        url = 'http://onlinesim.ru/api/getState.php'
        data = {'message_to_code': 1, 'tzid': tzid, 'apikey': self.api_key}
        while attempts < 30:
            attempts += 1
            time.sleep(3)
            if is_repeated:
                self.request_repeated_number_usage(tzid)
            resp = self._send_request(url, data)
            try:
                sms_code = resp[0].get('msg', None)
            except KeyError:
                logger.info("The time of the number usage has been expired")
                raise OnlineSimError
            if sms_code:
                if sms_code not in self.used_codes:
                    self.used_codes.add(sms_code)
                    return sms_code
        logger.info("Couldn't receive the SMS code.")
        return None

    def set_operation_ok(self, tzid):
        url = 'http://onlinesim.ru/api/setOperationOk.php'
        data = {'tzid': tzid, 'apikey': self.api_key}
        self._send_request(url, data)

    def request_repeated_number_usage(self, tzid):
        url = 'http://onlinesim.ru/api/setOperationRevise.php'
        data = {'tzid': tzid, 'apikey': self.api_key}
        self._send_request(url, data)

    @staticmethod
    def _send_request(url, data):
        while True:
            try:
                resp = requests.post(url, data=data, timeout=5)
                resp = resp.json()
                break
            except json.decoder.JSONDecodeError:
                logger.error('Сработала CloudFlare защита: %s. Код ошибки: %s', url, resp.status_code)
                time.sleep(3)
            except requests.exceptions.Timeout:
                logger.error('Не удалось получить ответ от: %s', url)

        logger.info(str(resp))
        return resp


class SmsActivateApi:

    def __init__(self, api_key):
        self.api_key = api_key
        self.url = 'http://sms-activate.ru/stubs/handler_api.php'

    def get_number(self):
        resp = requests.get(self.url, params={'api_key': self.api_key,
                                             'action': 'getNumbersStatus'})
        if 'BAD_KEY' in resp.text:
            raise SmsActivateError('Неверный API ключ')

        if not resp.json()['ot_0']:
            raise SmsActivateError('Закончились номера')

        resp = requests.get(self.url, params={'api_key': self.api_key,
                                             'action': 'getBalance'})
        logger.info(resp.text)
        if int(resp.text.partition(':')[2]) < 2:
            raise SmsActivateError('Недостаточно баланса для заказа номера')

        resp = requests.get(self.url, params={'api_key': self.api_key,
                                             'action': 'getNumber',
                                             'service': 'ot',
                                             'operator': 'beeline'})
        logger.info('Ответ от sms-activate на запрос получить новый номер: ' + resp.text)
        id, number = resp.text.split(':')[1:]
        number = '+' + number
        return id, number

    def set_status(self, id, status):
        set_status_params = {
        'api_key': self.api_key,
        'action': 'setStatus',
        'id': id
        }
        set_status_params['status'] = status
        resp = requests.get(self.url, params=set_status_params)
        logger.info('Ответ от sms-activate на запрос установить статус: ' + resp.text)

    def get_status(self, id, sms_code_prev=None):
        def get_sms():
            resp = requests.get(self.url, params={'api_key': self.api_key,
                                                  'action': 'getStatus',
                                                  'id': id})
            logger.info('Ответ от sms-activate на запрос получить статус: ' + resp.text)
            status, delimeter, smscode_msg = resp.text.partition(':')
            try:
                sms_code = re.search('\d+', smscode_msg).group()
            except AttributeError:
                sms_code = ''
            time.sleep(3)
            return status, sms_code

        attempts = 0
        if not sms_code_prev:
            status = ''
            while attempts < 20:
                status, sms_code = get_sms()
                if status == 'STATUS_OK':
                    return sms_code
                attempts += 1
        else:
            sms_code = sms_code_prev
            while attempts < 20:
                status, sms_code = get_sms()
                if sms_code != sms_code_prev:
                    return sms_code
                attempts += 1

        return None
