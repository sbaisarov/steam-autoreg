import enum
import struct
import time
import re
import datetime
import json
import logging
from typing import List
from imaplib import IMAP4, IMAP4_SSL

class GameOptions(enum.Enum):
    DOTA2 = ('570', '2')
    CS = ('730', '2')
    TF2 = ('440', '2')
    GIFTS = ('753', '1')
    CARDS = ('753', '6')
    PAYDAY2 = ('218620', '2')
    H1Z1 = ('433850', '1')
    PUBG = ('578080', '2')

    def __init__(self, app_id: str, context_id: str) -> None:
        self.app_id = app_id
        self.context_id = context_id

    @classmethod
    def appid_to_option(cls, appid):
        for game_option in cls:
            if appid == game_option.value[0]:
                return game_option
        raise Exception('This appid is not supported by GameOptions: %s' % appid)


logger = logging.getLogger("__main__")


def fetch_emaiL_code(email, email_passwd, login_name, subject):
    email_domain = email.partition('@')[2]
    if email_domain == 'yandex.ru' or email_domain == 'bubblemail.xyz':
        imap_server = 'imap.yandex.ru'
    else:
        imap_server = 'imap.mail.ru' # no full search support for this imap server

    date = datetime.datetime.today().strftime("%d-%b-%Y")
    regexpr = r'login to account (?:.+):\s+(.+)\s+'
    if 'Email address change request' in subject:
        regexpr = r'to update your email address:\s+(.+)\s+'

    while True:
        try:
            server = IMAP4_SSL(imap_server)
            server.login(email, email_passwd)
            server.select()
            time.sleep(10)
            attempts = 0
            mail_body = None
            while attempts < 20:
                typ, msgnums = server.search(
                    None, 'UNSEEN SINCE {} Subject "{}"'.format(date, subject))
                print(msgnums[0])
                print(msgnums[0].split()[-1])
                if msgnums[0]:
                    mail_body = server.fetch(msgnums[0].split()[-1], '(UID BODY[TEXT])')[1][0][1].decode('utf-8')
                    if login_name in mail_body:
                        break
                server.select()
                time.sleep(15)
                attempts += 1

            if not mail_body:
                raise Exception('The email with the steam guard code was not found.')
            guard_code = re.search(regexpr, mail_body).group(1).rstrip()
            print('Email found, guard code:', guard_code)
            return guard_code
        except (IMAP4.abort, IMAP4.error, ConnectionResetError) as err:
            print('Error while connecting to IMAP:', err)
            print('Reconnecting...')
            time.sleep(5)


def fetch_email_code_tempmail():
    pass


def text_between(text: str, begin: str, end: str) -> str:
    try:
        start = text.index(begin) + len(begin)
    except ValueError as err:
        print(err)
        print(text)
    end = text.index(end, start)
    return text[start:end]


def account_id_to_steam_id(account_id: str) -> str:
    first_bytes = int(account_id).to_bytes(4, byteorder='big')
    last_bytes = 0x1100001.to_bytes(4, byteorder='big')
    return str(struct.unpack('>Q', last_bytes + first_bytes)[0])


def steam_id_to_account_id(steam_id: str) -> str:
    return str(struct.unpack('>L', int(steam_id).to_bytes(8, byteorder='big')[4:])[0])


def price_to_float(price: str) -> float:
    return float(price[1:].split()[0])


def merge_items_with_descriptions_from_inventory(inventory_response: dict, game: GameOptions) -> dict:
    inventory = inventory_response['rgInventory']
    if isinstance(inventory, list):
        inventory = dict(inventory)
    descriptions = inventory_response['rgDescriptions']
    return merge_items(inventory.values(), descriptions, context_id=game.context_id)


def merge_items_with_descriptions_from_offers(offers_response: dict) -> dict:
    descriptions = {get_description_key(offer): offer for offer in offers_response['response'].get('descriptions', [])}
    received_offers = offers_response['response'].get('trade_offers_received', [])
    sent_offers = offers_response['response'].get('trade_offers_sent', [])
    offers_response['response']['trade_offers_received'] = list(
        map(lambda offer: merge_items_with_descriptions_from_offer(offer, descriptions), received_offers))
    offers_response['response']['trade_offers_sent'] = list(
        map(lambda offer: merge_items_with_descriptions_from_offer(offer, descriptions), sent_offers))
    return offers_response


def merge_items_with_descriptions_from_offer(offer: dict, descriptions: dict) -> dict:
    merged_items_to_give = merge_items(offer.get('items_to_give', []), descriptions)
    merged_items_to_receive = merge_items(offer.get('items_to_receive', []), descriptions)
    offer['items_to_give'] = merged_items_to_give
    offer['items_to_receive'] = merged_items_to_receive
    return offer


def merge_items(items: List[dict], descriptions: dict, **kwargs) -> dict:
    merged_items = {}
    for item in items:
        description_key = get_description_key(item)
        description = descriptions[description_key]
        item_id = item.get('id') or item['assetid']
        description['contextid'] = item.get('contextid') or kwargs['context_id']
        description['id'] = item_id
        description['amount'] = item['amount']
        merged_items[item_id] = description
    return merged_items


def get_description_key(item: dict) -> str:
    return item['classid'] + '_' + item['instanceid']


def update_session(client):
    client.session.cookies.clear()
    client.login(client.login_name, client.password,
                 client.mafile)


def convert_edomain_to_imap(email_domain, additional_hosts={}):
    host = None
    domains_and_hosts = {
        "imap.yandex.ru": ["yandex.ru"],
        "imap.mail.ru": ["mail.ru", "bk.ru", "list.ru", "inbox.ru", "mail.ua"],
        "imap.rambler.ru": ["rambler.ru", "lenta.ru", "autorambler.ru", "myrambler.ru", "ro.ru", "rambler.ua"],
        "imap.gmail.com": ["gmail.com", ],
        "imap.mail.yahoo.com": ["yahoo.com", ],
        "imap-mail.outlook.com": ["outlook.com", "hotmail.com"],
        "imap.aol.com": ["aol.com", ]
    }
    for imap_host, domains in additional_hosts.items():
        try:
            list(map(lambda domain: domains_and_hosts[imap_host].append(domain), domains))
        except:
            domains_and_hosts[imap_host] = domains
    for host, domains in domains_and_hosts.items():
        if email_domain in domains:
            return host

    return host
