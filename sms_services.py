import requests
import re
import time
import logging

class OnlineSimError(Exception): pass
class SmsActivateError(Exception): pass

logger = logging.getLogger(__name__)

class OnlineSimApi():

    def __init__(self, api_key):
        self.api_key = api_key
        self.used_codes = set()


    def request_new_number(self):
        resp = requests.post('http://onlinesim.ru/api/getNum.php',
                             data={'service': 'Steam',
                             'apikey': self.api_key,
                             'form': '1'}).json()
        try:
            tzid = resp['tzid']
        except KeyError:
            raise OnlineSimError(resp['response'])
        return tzid


    def get_number(self, tzid):
        resp = requests.post('http://onlinesim.ru/api/getState.php',
                             data={'message_to_code': 1, 'tzid': tzid,
                                   'apikey': self.api_key}).json()
        logger.info(str(resp))
        try:
            number = resp[0]['number']
        except (KeyError, IndexError):
            raise OnlineSimError(resp['response'])
        return number


    def get_sms_code(self, tzid, is_repeated=False):
        attempts = 0
        while attempts < 30:
            time.sleep(3)
            if is_repeated:
                self.request_repeated_number_usage(tzid)
            resp = requests.post('http://onlinesim.ru/api/getState.php',
                                 data={'message_to_code': 1, 'tzid': tzid,
                                       'apikey': self.api_key}).json()
            logger.info(str(resp))
            sms_code = resp[0].get('msg', None)
            if is_repeated:
                if sms_code not in self.used_codes:
                    self.used_codes.add(sms_code)
                    return sms_code
            else:
                if sms_code:
                    self.used_codes.add(sms_code)
                    return sms_code
            attempts += 1

        return None


    def set_operation_ok(self, tzid):
        resp = requests.post('http://onlinesim.ru/api/setOperationOk.php',
                             data={'tzid': tzid, 'apikey': self.api_key})
        logger.info(resp.text)


    def request_repeated_number_usage(self, tzid):
        resp = requests.post('http://onlinesim.ru/api/setOperationRevise.php',
                                 data={'tzid': tzid, 'apikey': self.api_key})
        logger.info(resp.text)


class SmsActivateApi():

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
