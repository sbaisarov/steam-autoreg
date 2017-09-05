from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import showwarning
import logging
import urllib
import os
import sys
import datetime
import uuid
import json
import time
import queue
import traceback
import threading

from pkgutil import iter_modules

installed_modules = [item[1] for item in iter_modules()]
if 'requests' not in installed_modules:
    print("Installing packages. Please wait...")
    os.system('pip install bs4 rsa')
    os.system('pip install https://github.com/Shamanovski/requests/archive/master.zip')
    print("The Installation is complete")

import requests

from steampy.client import SteamClient
from steampy.guard import generate_one_time_code
from steamreg import *
from sms_services import *

for dir_name in ('новые_аккаунты', 'загруженные_аккаунты'):
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

if not os.path.exists('database/userdata.txt'):
    with open('database/userdata.txt', 'w') as f:
        f.write('{}')

logging.getLogger("requests").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
handler = logging.FileHandler('database/logs.txt', 'w', encoding='utf-8')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

def uncaught_exceptions_handler(type, value, tb):
    logger.critical("Uncaught exception: {0} {1}\n{2}".format(type, value, traceback.format_tb(tb)))
sys.excepthook = uncaught_exceptions_handler

steamreg = SteamRegger()

class MainWindow:

    def __init__(self, parent):
        self.parent = parent
        frame = Frame(self.parent)
        with open('database/userdata.txt', 'r') as f:
            self.userdata = json.load(f)

        success = self.authorize_user()
        if not success:
            self.deploy_activation_widgets(frame)
            return

        self.manifest_path = ''
        self.accounts_path = ''
        self.email_boxes_path = ''
        self.email_boxes_data = None
        self.manifest_data = None
        self.old_accounts = None
        self.autoreg = IntVar()
        self.import_mafile = IntVar()
        self.mobile_bind = IntVar()
        self.fold_accounts = IntVar()
        self.onlinesim_api_key = StringVar()
        self.rucaptcha_api_key = StringVar()
        self.new_accounts_amount = IntVar()
        self.accounts_per_number = IntVar()
        self.email_domain = StringVar()

        self.status_bar = StringVar()

        if self.userdata:
            self.set_attributes()

        self.menubar = Menu(parent)
        parent['menu'] = self.menubar
        # self.menubar.add_command(label="Путь к аккаунтам", command=self.accounts_open)
        self.menubar.add_command(label="Путь к SDA Manifest", command=self.manifest_open)
        self.menubar.add_command(label="Загрузить свои почты", command=self.email_boxes_open)

        onlinesim_apikey_label = Label(frame, text='onlinesim api key:')
        onlinesim_apikey_label.grid(row=0, column=0, pady=5, sticky=W)
        onlinesim_apikey_entry = Entry(frame, textvariable=self.onlinesim_api_key)
        onlinesim_apikey_entry.grid(row=0, column=1, pady=5, padx=5, sticky=W)

        onlinesim_apikey_label = Label(frame, text='rucaptcha api key:')
        onlinesim_apikey_label.grid(row=1, column=0, pady=5, sticky=W)
        onlinesim_apikey_entry = Entry(frame, textvariable=self.rucaptcha_api_key)
        onlinesim_apikey_entry.grid(row=1, column=1, pady=5, padx=5, sticky=W)

        new_accounts_amount_label = Label(frame, text='Количество аккаунтов для регистрации:')
        new_accounts_amount_label.grid(row=2, column=0, pady=5, sticky=W)
        new_accounts_amount_entry = Entry(frame, textvariable=self.new_accounts_amount, width=4)
        new_accounts_amount_entry.grid(row=2, column=1, pady=5, padx=5, sticky=W)

        ctr_label = Label(frame, text='Количество аккаунтов на 1 номер:')
        ctr_label.grid(row=3, column=0, pady=5, sticky=W)
        ctr_entry = Entry(frame, textvariable=self.accounts_per_number, width=2)
        ctr_entry.grid(row=3, column=1, pady=5, padx=5, sticky=W)

        ctr_label = Label(frame, text='Домен для email (по усмотрению, без @):')
        ctr_label.grid(row=4, column=0, pady=5, sticky=W)
        ctr_entry = Entry(frame, textvariable=self.email_domain)
        ctr_entry.grid(row=4, column=1, pady=5, padx=5, sticky=W)

        autoreg_checkbutton = Checkbutton(frame, text='Создавать новые аккаунты',
                                          variable=self.autoreg, command=lambda: self.toogle_menu("Путь к аккаунтам"))
        autoreg_checkbutton.grid(row=5, column=0, sticky=W)
        mafile_checkbutton = Checkbutton(frame, text='Импортировать maFile в SDA',
                                         variable=self.import_mafile)
        mafile_checkbutton.grid(row=5, column=1, pady=3)
        mobile_bind_checkbutton = Checkbutton(frame, text='Привязывать Mobile Guard',
                                              variable=self.mobile_bind)
        mobile_bind_checkbutton.grid(row=6, column=0, pady=3, sticky=W)
        mobile_bind_checkbutton = Checkbutton(frame, text='Раскладывать по папкам',
                                              variable=self.fold_accounts)
        mobile_bind_checkbutton.grid(row=6, column=1, pady=3, sticky=W)

        start_button = Button(frame, text='Начать', command=self.start_process,
                              bg='#CEC8C8', relief=GROOVE, width=50)
        start_button.grid(pady=10, columnspan=2)

        log_frame = Frame(self.parent)
        log_label = Label(log_frame, text='Логи:')
        log_label.grid(row=0, column=0, pady=5, sticky=W)
        scrollbar = Scrollbar(log_frame, orient=VERTICAL)
        self.log_box = Listbox(log_frame, yscrollcommand=scrollbar.set)
        self.log_box.grid(row=1, column=0, sticky=NSEW)
        self.log_box.bind('<Enter>', self.freeze_log)
        self.log_box.bind('<Leave>', self.unfreeze_log)
        self.log_frozen = False
        scrollbar["command"] = self.log_box.yview
        scrollbar.grid(row=1, column=1, sticky=NS)
        scrollbar.bind('<Enter>', self.freeze_log)
        scrollbar.bind('<Leave>', self.unfreeze_log)

        frame.grid(row=0, column=0)
        log_frame.grid(row=1, column=0, sticky=NSEW)
        log_frame.columnconfigure(0, weight=999)
        log_frame.columnconfigure(1, weight=1)

        status_bar = Label(log_frame, anchor=W, text='Готов...', textvariable=self.status_bar)
        status_bar.grid(row=2, column=0, columnspan=2, sticky=W, pady=5)
        caption_label = Label(log_frame, text='by Shamanovsky')
        caption_label.grid(row=2, column=0, sticky=E)

    def set_attributes(self):
        for attr, value in self.userdata.items():
            if attr == 'manifest_path':
                self.load_manifest(value)
            else:
                obj = self.__getattribute__(attr)
                obj.set(value)

    def add_log(self, message):
        self.log_box.insert(END, message)
        if not self.log_frozen:
            self.log_box.yview(END)

    def freeze_log(self, *ignore):
        self.log_frozen = True

    def unfreeze_log(self, *ignore):
        self.log_frozen = False

    def toogle_menu(self, label):
        if self.autoreg.get():
            try:
                self.menubar.delete("Путь к аккаунтам")
            except TclError:
                pass
        else:
            self.menubar.add_command(label="Путь к аккаунтам", command=self.accounts_open)

    def run_process(self):
        if not self.check_input():
            return
        self.save_input()
        try:
            if self.mobile_bind.get():
                self.registrate_with_binding()
            elif self.autoreg.get():
                self.registrate_without_binding()
        except (OnlineSimError, RuCaptchaError) as err:
            showwarning(err.__class__.__name__, err,
                        parent=self.parent)
            logger.critical(err)
        except Exception:
            error = traceback.format_exc()
            showwarning("Внутренняя ошибка программы", error)
            logger.critical(error)

        self.status_bar.set('Готов...')

    def check_input(self):
        if not self.manifest_path and self.import_mafile.get():
            showwarning("Ошибка", "Не указан путь к manifest файлу Steam Desktop Authenticator",
                        parent=self.parent)
            return False

        if not self.rucaptcha_api_key.get() and self.autoreg.get():
            showwarning("Ошибка", "Не указан api ключ RuCaptcha")
            return False

        if self.autoreg.get():
            try:
                self.check_rucaptcha_key()
            except RuCaptchaError as err:
                showwarning("Ошибка RuCaptcha", err, parent=self.parent)
                return False
            try:
                if self.new_accounts_amount.get() <= 0:
                    raise ValueError
            except (TclError, ValueError):
                showwarning("Ошибка", "Количество аккаунтов для "
                                      "регистрации должно составлять от 1 до 33",
                            parent=self.parent)
                return False

        if self.mobile_bind.get():
            try:
                if not 0 < self.accounts_per_number.get() <= 30:
                    raise ValueError
            except (TclError, ValueError):
                showwarning("Ошибка", "Введите корректное число аккаунтов, "
                                      "связанных с 1 номером (больше нуля но меньше 30-и).",
                            parent=self.parent)
                return False
        return True

    def save_input(self):
        for field, value in self.__dict__.items():
            if field in ('status_bar', 'license'):
                continue
            if issubclass(value.__class__, Variable) or 'manifest_path' in field:
                try:
                    value = value.get()
                except AttributeError:
                    pass
                self.userdata[field] = value

    def registrate_without_binding(self):
        new_accounts_amount = self.new_accounts_amount.get()
        self.status_bar.set('Создаю аккаунты, решаю капчи...')
        threads = []
        for _ in range(20):
            t = RegistrationThread(self, new_accounts_amount) # transfer main window object
            t.start()
            threads.append(t)

        for thread in threads:
            thread.join()
            if thread.error:
                error_origin, error_text = thread.error
                showwarning("Ошибка %s" % error_origin, error_text)
                return

        RegistrationThread.counter = 0

    def registrate_with_binding(self):
        onlinesim_api_key = self.onlinesim_api_key.get()
        if not onlinesim_api_key:
            showwarning("Ошибка", "Не указан api ключ для onlinesim.ru", parent=self.parent)
            return

        if not self.accounts_path and not self.autoreg.get():
            showwarning("Ошибка", "Не указан путь к файлу с данными от аккаунтов. "
                                  "Если у вас нет своих аккаунтов, то поставьте галочку 'Создавать новые аккаунты'",
                        parent=self.parent)
            return

        accounts = self.new_accounts_generator() if self.autoreg.get() else self.old_account_generator()
        sms_service = OnlineSimApi(onlinesim_api_key)
        binder = Binder(self, sms_service)
        for accounts_package in accounts:
            binder.bind_accounts(accounts_package)

    def new_accounts_generator(self):
        ctr = 0
        new_accounts_amount = self.new_accounts_amount.get()
        accounts_per_number = self.accounts_per_number.get()
        while ctr < new_accounts_amount:
            self.status_bar.set('Создаю аккаунты, решаю капчи...')
            new_accounts = []
            threads = []
            remainder = new_accounts_amount - ctr
            if remainder < accounts_per_number:
                accounts_per_number = remainder
            for _ in range(accounts_per_number):
                t = RegistrationThread(self, accounts_per_number, new_accounts)  # transfer main window object
                t.start()
                threads.append(t)
                ctr += 1
            for thread in threads:
                thread.join()
                if thread.error:
                    error_origin, error_text = thread.error
                    showwarning("Ошибка %s" % error_origin, error_text)
                    return
            RegistrationThread.counter = 0
            yield new_accounts

    def authorize_user(self):
        key = ''
        if os.path.exists('database/key.txt'):
            with open('database/key.txt', 'r') as f:
                user_data = json.load(f)
            resp = requests.post('https://shamanovski.pythonanywhere.com/',
                                 data={
                                         'login': user_data['login'],
                                         'key': user_data['key'],
                                         'uid': self.get_node()
                                 }).json()
        else:
            return False

        return resp['success']

    def check_license(self, frame):
        key, login = self.license_key_entry.get(), self.login_entry.get()
        if not all((key, login)):
            showwarning('Ошибка', 'Заполните все поля')
            return
        resp = requests.post('https://shamanovski.pythonanywhere.com/',
                             data={
                                     'login': login,
                                     'key': key,
                                     'uid': self.get_node()
                             }).json()
        if not resp['success']:
            showwarning('Ошибка', 'Неверный ключ либо попытка активации с неавторизованного устройства')
            return

        with open('database/key.txt', 'w') as f:
            json.dump({'login': login, 'key': key}, f)

        top = Toplevel(self.parent)
        top.title("Успешно!")
        top.geometry('230x50')
        msg = ('Программа активирована. Приятного пользования!')
        msg = Message(top, text=msg, aspect=500)
        msg.grid()

        self.__init__(self.parent)

    def deploy_activation_widgets(self, frame):
        self.license = StringVar()
        license_key_label = Label(frame, text='Введите ключ активации программы:')
        license_key_label.grid(row=0, column=0, pady=5, sticky=W)
        self.license_key_entry = Entry(frame)
        self.license_key_entry.grid(row=0, column=1, pady=5, padx=5, sticky=W)
        login_label = Label(frame, text='Ваш логин:')
        login_label.grid(row=1, column=0, pady=5, sticky=W)
        self.login_entry = Entry(frame)
        self.login_entry.grid(row=1, column=1, pady=5, padx=5, sticky=W)
        check_license_bttn = Button(frame, text='Проверить лицензию',
                                    command=lambda: self.check_license(frame),
                                    relief=GROOVE)
        check_license_bttn.grid(sticky=W, padx=20, pady=5)
        frame.grid(row=0, column=0)

    def check_rucaptcha_key(self):
        resp = requests.post('http://rucaptcha.com/res.php',
                             data={'key': self.rucaptcha_api_key.get().strip(),
                                   'action': 'getbalance'})
        logger.info(resp.text)
        if 'ERROR_ZERO_BALANCE' in resp.text:
            raise RuCaptchaError('На счету нулевой баланс')
        elif 'ERROR_WRONG_USER_KEY' in resp.text:
            raise RuCaptchaError('Неправильно введен API ключ')

    @staticmethod
    def get_node():
        mac = uuid.getnode()
        if (mac >> 40) % 2:
            raise OSError('Не удается авторизовать устройство. Обратитесь в тех.поддержку.')
        return hex(mac)

    def start_process(self):
        if len(threading.enumerate()) == 1:
            t = threading.Thread(target=self.run_process)
            t.daemon = True
            t.start()

    def accounts_open(self):
        dir = (os.path.dirname(self.accounts_path)
               if self.accounts_path is not None else '.')
        accounts_path = askopenfilename(
                    title='логин:пасс аккаунтов',
                    initialdir=dir,
                    filetypes=[('Text file', '*.txt')],
                    defaultextension='.txt', parent=self.parent)
        if accounts_path:
            return self.load_accounts(accounts_path)

    def load_accounts(self, accounts_path):
        try:
            with open(accounts_path, 'r') as f:
                self.old_accounts = [i.rstrip().split(':') for i in f.readlines()]
        except (EnvironmentError, TypeError):
            return

        self.status_bar.set("Файл загружен: %s" % os.path.basename(accounts_path))
        self.accounts_path = accounts_path

    def old_account_generator(self):
        start = 0
        end = span = self.accounts_per_number.get()
        while start < len(self.old_accounts):
            yield self.old_accounts[start:end]
            start, end = end, end + span

    def email_boxes_open(self):
        dir_ = (os.path.dirname(self.emails_path)
                if self.email_boxes_path is not None else '.')
        emails_path = askopenfilename(
                    title='Email адреса',
                    initialdir=dir_,
                    filetypes=[('Text file', '*.txt')],
                    defaultextension='.txt', parent=self.parent)
        if emails_path:
            return self.load_emails(emails_path)

    def load_emails(self, emails_path):
        try:
            with open(emails_path, 'r') as f:
                self.email_boxes_data = [i.strip() for i in f.readlines()]
        except (EnvironmentError, TypeError):
            return

    def manifest_open(self):
        dir_ = (os.path.dirname(self.manifest_path)
                if self.manifest_path is not None else '.')
        manifest_path = askopenfilename(
                    title='SDA manifest',
                    initialdir=dir_,
                    filetypes=[('manifest', '*.json')],
                    defaultextension='.json', parent=self.parent)
        if manifest_path:
            return self.load_manifest(manifest_path)

    def load_manifest(self, manifest_path):
        try:
            with open(manifest_path, 'r') as f:
                self.manifest_data = json.load(f)
            self.manifest_path = manifest_path
        except (EnvironmentError, TypeError):
            pass

    def app_quit(self, *ignore):
        with open('database/userdata.txt', 'w') as f:
            json.dump(self.userdata, f)

        self.parent.destroy()

class RegistrationThread(threading.Thread):

    counter = 0
    lock = threading.Lock()

    def __init__(self, window, amount, result=None):
        threading.Thread.__init__(self)
        self.daemon = True
        self.window = window
        self.amount = amount
        self.result = result
        self.error = None

    def run(self):
        while RegistrationThread.counter < self.amount:
            RegistrationThread.counter += 1
            try:
                self.registrate_account()
            except Exception as err:
                self.error = (err.__class__.__name__, err)
                logger.critical(traceback.format_exc())
                return

    def registrate_account(self):

        login, passwd = steamreg.create_account(self.window.rucaptcha_api_key.get().strip(),
                                                self.window.email_domain.get())
        logger.info('Аккаунт: %s:%s', login, passwd)
        with RegistrationThread.lock:
            self.window.add_log('Аккаунт зарегистрирован: %s %s' % (login, passwd))
            if not self.window.mobile_bind.get():
                self.save_unattached_account(login, passwd)
        steam_client = SteamClient()
        while True:
            try:
                with RegistrationThread.lock:
                    steam_client.login(login, passwd)
                break
            except AttributeError:
                time.sleep(3)
        steamreg.activate_account(steam_client)
        steamreg.remove_intentory_privacy(steam_client)
        if self.result is not None:
            self.result.append((login, passwd))

    def save_unattached_account(self, login, passwd):
        with open('непривязанные_аккаунты.txt', 'a+') as f:
            f.write('%s:%s\n' % (login, passwd))

    @staticmethod
    def generate_mailbox():
        ssl_option = {"check_hostname": False, "cert_reqs": 0, "ca_certs": "cacert.pem"}
        ws = create_connection('wss://dropmail.me/websocket', sslopt=ssl_option)
        mailbox = ws.recv().partition(':')[0].lstrip('A')
        ws.recv()  # skip the message with domains
        return mailbox, ws

    @staticmethod
    def fetch_email_code(websocket):
        regexr = r'to update your email address:\s+(.+)\s+'
        opcode, data = websocket.recv_data()
        mail = json.loads(data.decode('utf-8').lstrip('I'))['text']
        guard_code = re.search(regexr, mail).group(1).rstrip()
        return guard_code

class Binder:

    def __init__(self, window, sms_service):
        self.window = window
        self.sms_service = sms_service
        self.error = None

    def bind_accounts(self, accounts_package):
        tzid, number, is_repeated = self.get_new_number()
        self.window.status_bar.set('Делаю привязку Mobile Guard...')
        for account_data in accounts_package:
            login, passwd = account_data[:2]
            logger.info('Аккаунт: %s:%s', login, passwd)
            insert_log = self.log_wrapper(login)
            insert_log('Номер: ' + number)
            insert_log('Логинюсь в аккаунт')
            try:
                steam_client = steamreg.mobile_login(login, passwd)
            except SteamAuthError as err:
                insert_log(err)
                continue

            if steamreg.is_phone_attached(steam_client):
                insert_log('К аккаунту уже привязан номер')
                continue

            try:
                sms_code, mobguard_data, number, tzid = self.add_authenticator(insert_log, steam_client,
                                                                               number, tzid, is_repeated)
            except SteamAuthError:
                error = 'Не удается привязать номер к аккаунту: ' + login
                logger.error(error)
                insert_log(error)
                continue
            is_repeated = True
            insert_log('Делаю запрос на привязку гуарда...')
            steamreg.finalize_authenticator_request(steam_client, mobguard_data, sms_code)
            mobguard_data['account_password'] = passwd
            self.save_attached_account(mobguard_data, login, passwd, number)
            if not self.window.autoreg.get():
                steamreg.activate_account(steam_client)
                steamreg.remove_intentory_privacy(steam_client)
            insert_log('Guard успешно привязан')

        self.sms_service.set_operation_ok(tzid)

    def add_authenticator(self, insert_log, steam_client, number, tzid, is_repeated):
        while True:
            insert_log('Делаю запрос Steam на добавление номера...')
            response = steamreg.addphone_request(steam_client, number)
            if not response['success']:
                if "we couldn't send an SMS to your phone" in response.get('error_text', ''):
                    insert_log('Стим сообщил о том, ему не удалось отправить SMS')
                    insert_log('Меняю номер...')
                    tzid, number, is_repeated = self.get_new_number(tzid)
                    insert_log('Новый номер: ' + number)
                    time.sleep(5)
                    continue
                raise SteamAuthError('Steam addphone request failed: %s' % number)

            insert_log('Жду SMS код...')
            try:
                sms_code = self.sms_service.get_sms_code(tzid, is_repeated)
                if not is_repeated:
                    is_repeated = True
                if not sms_code:
                    insert_log('Не доходит SMS. Пробую снова...')
                    continue
            except OnlineSimError:
                insert_log('Истекло время аренды номера: ' + number)
                insert_log('Меняю номер...')
                tzid, number, is_repeated = self.get_new_number(tzid)
                insert_log('Новый номер: ' + number)
                continue

            mobguard_data = steamreg.add_authenticator_request(steam_client)
            response = steamreg.checksms_request(steam_client, sms_code)
            if 'The SMS code is incorrect' in response.get('error_text', ''):
                insert_log('Неверный SMS код %s. Пробую снова...' % sms_code)
                continue
            return sms_code, mobguard_data, number, tzid

    def get_new_number(self, tzid=0):
        if tzid:
            self.sms_service.set_operation_ok(tzid)
            self.sms_service.used_codes.clear()
        is_repeated = False
        tzid = self.sms_service.request_new_number()
        number = self.sms_service.get_number(tzid)
        return tzid, number, is_repeated

    def save_attached_account(self, mobguard_data, login, passwd, number):
        if self.window.mobile_bind.get():
            if self.window.autoreg.get():
                accounts_dir = 'новые_аккаунты'
                if self.window.fold_accounts.get():
                    os.makedirs(login)
                    accounts_dir += r'\%s' % login
            else:
                accounts_dir = 'загруженные_аккаунты'

        steamid = mobguard_data['Session']['SteamID']
        txt_path = os.path.join(accounts_dir, login + '.txt')
        mafile_path = os.path.join(accounts_dir, login + '.maFile')

        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write('{}:{}\nДата привязки Guard: {}\nНомер: {}\nSteamID: {}\nEmail: {}\nRCODE: {}'.format(
                    login, passwd, str(datetime.date.today()), number, steamid, steamreg.email, mobguard_data['revocation_code']))

        with open('привязанные_аккаунты.txt', 'a+') as f:
            f.write('%s:%s\n' % (login, passwd))

        if self.window.import_mafile.get():
            mafile_path = os.path.join(os.path.dirname(self.window.manifest_path), login + '.maFile')
            data = {
                "encryption_iv": None,
                "encryption_salt": None,
                "filename": login + '.maFile',
                "steamid": int(steamid)
            }
            self.window.manifest_data["entries"].append(data)
            with open(self.window.manifest_path, 'w') as f:
                json.dump(self.window.manifest_data, f)

        with open(mafile_path, 'w') as f:
            json.dump(mobguard_data, f, separators=(',', ':'))

    def log_wrapper(self, login):
        def insert_log(text):
            self.window.add_log('%s (%s)' % (text, login))
        return insert_log

root = Tk()
window = MainWindow(root)
root.iconbitmap('database/app.ico')
root.title('Steam Auto Authenticator v0.6')
root.protocol("WM_DELETE_WINDOW", window.app_quit)
root.mainloop()
