import imaplib
import time
import re
from requests import Session
from steampy.utils import convert_edomain_to_imap
from steampy.login import LoginExecutor
from controller import InvalidEmail, RuCaptcha


rucaptcha = RuCaptcha("57a13e679aa1817a1669fca25d677fe9")


def authorize_email(email, email_password):
    email_domain = re.search(r"@(.+$)", email).group(1)
    imap_host = convert_edomain_to_imap(email_domain,  LoginExecutor.IMAP_HOSTS)

    if imap_host is None:
        raise InvalidEmail("Не удается найти imap host для данного email домена: %s" % email_domain)
    server = imaplib.IMAP4_SSL(imap_host)
    server.login(email, email_password)
    server.select()
    return server


def fetch_confirmation_link(email, email_password, creationid):
    server = authorize_email(email, email_password)
    attempts = 0
    while attempts < 5:
        attempts += 1
        typ, data = server.search(None, 'ALL')
        uid = data[0].split()[-1]
        result, data = server.uid("fetch", uid, '(UID BODY[TEXT])')
        mail = data[0][1].decode('utf-8')
        link = re.search(r'(https://.+newaccountverification.+?)\r', mail)
        if link is None:
            time.sleep(5)
            continue
        link = link.group(1)
        creationid_from_link = re.search(r"creationid=(\w+)", link)
        if creationid_from_link is not None and creationid == creationid_from_link.group(1):
            server.close()
            return link
        time.sleep(5)
    server.close()
    raise InvalidEmail("Не удается получить письмо от Steam")


def confirm_email(session, gid, token, email: str, sitekey):
    email_name, _, email_password = email.partition(":")
    while True:
        data = {
            'captcha_text': token,
            'captchagid': gid,
            'email': email_name
        }
        resp = session.post('https://store.steampowered.com/join/ajaxverifyemail', data=data).json()
        creationid = resp['sessionid']
        if not creationid:
            captcha_id = rucaptcha.generate_recaptcha(sitekey)
            token = rucaptcha.resolve_captcha(captcha_id)
            continue

        time.sleep(10)  # wait some time until email has been received
        link = fetch_confirmation_link(email_name, email_password, creationid)
        session.get(link)
        return creationid


def main():
    session = Session()
    session.headers.update({'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                           'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36'),
                            'Accept-Language': 'q=0.8,en-US;q=0.6,en;q=0.4'})
    session.headers.update({'Host': 'store.steampowered.com'})
    response = session.get('https://store.steampowered.com/join/refreshcaptcha/?count=1', timeout=30).json()
    gid, sitekey = response['gid'], response['sitekey']
    captcha_id = rucaptcha.generate_recaptcha(sitekey)
    token = rucaptcha.resolve_captcha(captcha_id)
    email = "awdasdwadawd@yandex.ru:viga9982"  # твоя почта
    creationid = confirm_email(session, gid, token, email, sitekey)
    data = {
        'accountname': "rtuyrturtyr",  # логин для стим аккаунта
        'password': "asdgfdш77d4783",  # пароль для стим аккаунта
        'count': '32',
        'lt': '0',
        'creation_sessionid': creationid
    }
    resp = session.post('https://store.steampowered.com/join/createaccount/',
                        data=data, timeout=25)
    print(resp.text)


main()
