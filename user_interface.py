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
import traceback
import threading

from pkgutil import iter_modules

installed_modules = [item[1] for item in iter_modules()]
if 'requests' not in installed_modules:
    os.system('pip install requests bs4 rsa')

import requests

from steampy.guard import generate_one_time_code
from steamreg import *
from sms_services import *

for dir_name in ('new_accounts', 'old_accounts'):
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

if not os.path.exists('database/userdata.txt'):
    with open('database/userdata.txt', 'w') as f:
        f.write('{}')

lock = threading.Lock()

class MainWindow():

    def __init__(self, parent):
        self.parent = parent
        frame = Frame(self.parent)
        with open('database/userdata.txt', 'r') as f:
            self.userdata = json.load(f)

        success = self.authorize_user()
        if not success:
            self.deploy_activation_widgets(frame)
            return

        self.steamreg = SteamRegger()

        self.manifest_path = None
        self.accounts_path = None
        self.manifest_data = None
        self.accounts = None
        self.autoreg = IntVar()
        self.import_mafile = IntVar()
        self.mobile_bind = IntVar()
        self.onlinesim_api_key = StringVar()
        self.rucaptcha_api_key = StringVar()
        self.new_accounts_amount = IntVar()
        self.accounts_per_number = IntVar()

        self.status_bar = StringVar()

        if self.userdata:
            self.set_attributes()

        menubar = Menu(parent)
        parent['menu'] = menubar
        menubar.add_command(label="Путь к аккаунтам", command=self.accounts_open)
        menubar.add_command(label="Путь к SDA Manifest", command=self.manifest_open)

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

        autoreg_checkbutton = Checkbutton(frame, text='Создавать новые аккаунты',
                                          variable=self.autoreg)
        autoreg_checkbutton.grid(row=4, column=0, sticky=W)
        mafile_checkbutton = Checkbutton(frame, text='Импортировать maFile в SDA',
                                         variable=self.import_mafile)
        mafile_checkbutton.grid(row=4, column=1, pady=3)
        mobile_bind_checkbutton = Checkbutton(frame, text='Привязывать Mobile Guard',
                                              variable=self.mobile_bind)
        mobile_bind_checkbutton.grid(row=5, column=0, pady=3, sticky=W)
        start_button = Button(frame, text='Начать', command=self.start_process,
                              bg='#CEC8C8', relief=GROOVE, width=50)
        start_button.grid(pady=10, columnspan=2)

        log_frame = Frame(self.parent)
        errorlog_label = Label(log_frame, text='Логи:')
        errorlog_label.grid(row=0, column=0, pady=5, sticky=W)
        scrollbar = Scrollbar(log_frame, orient=VERTICAL)
        self.log_box = Listbox(log_frame, yscrollcommand=scrollbar.set)
        self.log_box.grid(row=1, column=0, sticky=NSEW)
        scrollbar["command"] = self.log_box.yview
        scrollbar.grid(row=1, column=1, sticky=NS)

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
            elif attr == 'accounts_path':
                self.load_accounts(value)
            else:
                obj = self.__getattribute__(attr)
                obj.set(value)

    def run_process(self):
        if not self.manifest_path and self.import_mafile.get():
            showwarning("Ошибка", "Не указан путь к manifest файлу Steam Desktop Authenticator",
                        parent=self.parent)
            return

        if not self.rucaptcha_api_key.get() and self.autoreg.get():
            showwarning("Ошибка", "Не указан api ключ RuCaptcha")
            return

        for field, value in self.__dict__.items():
            if field in ('status_bar', 'license'):
                continue
            if issubclass(value.__class__, Variable) or 'path' in field:
                try:
                    value = value.get()
                except AttributeError:
                    pass
                self.userdata[field] = value

        try:
            if self.autoreg.get():
                self.check_rucaptcha_key()
            if self.mobile_bind.get():
                self.registrate_with_binding()
            else:
                self.registrate_without_binding()
        except OnlineSimError as err:
            showwarning("Ошибка onlinesim.ru", err)
        except RuCaptchaError as err:
            showwarning("Ошибка rucaptcha.com", err)
        except SteamCaptchaError as err:
            showwarning('Ошибка', err)
        except Exception as err:
            error = traceback.format_exc()
            showwarning('Ошибка.', error)
            logger.critical(error)
        finally:
            self.status_bar.set('Готов...')

    def registrate_without_binding(self):
        if not self.new_accounts_amount.get():
            showwarning("Ошибка", "Укажите количество аккаунтов для регистрации")
            return

        self.status_bar.set('Создаю аккаунты, решаю капчи...')
        rucaptcha_api_key = self.rucaptcha_api_key.get()
        threads = []
        for _ in range(20):
            t = threading.Thread(target=self.registrate_account)
            t.daemon = True
            t.start()
            threads.append(t)

        for thread in threads:
            thread.join()

    def registrate_with_binding(self):
        onlinesim_api_key = self.onlinesim_api_key.get()
        if not onlinesim_api_key:
            showwarning("Ошибка", "Не указан api ключ для onlinesim.ru", parent=self.parent)
            return

        if not self.accounts_path and not self.autoreg.get():
            showwarning("Ошибка", ("Не указан путь к файлу с данными от аккаунтов. "
                                   "Если у вас нет своих аккаунтов, то поставьте галочку 'Создавать новые аккаунты'"),
                        parent=self.parent)
            return

        try:
            accounts_per_number = self.accounts_per_number.get()
            if not 0 < accounts_per_number <= 20:
                raise ValueError
        except (TypeError, ValueError):
            showwarning("Ошибка", "Введите корректное число аккаунтов, "
                        "связанных с 1 номером (больше нуля но меньше 20-и).", parent=self.parent)
            return

        sms_service = OnlineSimApi(onlinesim_api_key)
        tzid = 0
        ctr = 0
        err = None
        is_first_iteration = True
        accounts = self.accounts_generator() if self.autoreg.get() else self.accounts
        for data in accounts:
            login, passwd = data[:2]
            logger.info('account data: %s %s', login, passwd)

            if ctr == accounts_per_number or is_first_iteration:
                tzid, number, is_repeated, ctr = self.get_new_number(sms_service, tzid)
                is_first_iteration = False

            self.log_box.insert(END, 'Привязываю Guard к аккаунту: %s %s' % (login, passwd))
            self.status_bar.set('Логинюсь в аккаунт...')
            try:
                steam_client = self.steamreg.mobile_login(login, passwd)
            except SteamAuthError as err:
                self.log_box.insert(END, err)
                continue

            while True:
                self.status_bar.set('Делаю запрос Steam на добавление номера...')
                is_number_valid = self.steamreg.steam_addphone_request(steam_client, number)
                if not is_number_valid:
                    if self.steamreg.has_phone_attached(steam_client):
                        self.log_box.insert(END, 'К аккаунту %s уже привязан номер' % login)
                        break

                    self.log_box.insert(END, 'Стим сообщил о том, что номер не подходит')
                    time.sleep(5)
                    tzid, number, is_repeated, ctr = self.get_new_number(sms_service, tzid)
                    continue
                self.status_bar.set('Жду SMS код...')
                sms_code = sms_service.get_sms_code(tzid, is_repeated=is_repeated)
                is_repeated = True
                if not sms_code:
                    self.log_box.insert(END, 'Не доходит SMS. Меняю номер...')
                    tzid, number, is_repeated, ctr = self.get_new_number(sms_service, tzid)
                    continue
                mobguard_data = self.steamreg.steam_add_authenticator_request(steam_client)
                success = self.steamreg.steam_checksms_request(steam_client, sms_code)
                if not success:
                    self.log_box.insert('Неверный SMS код. Пробую снова...')
                    time.sleep(5)
                    continue
                break

            if not is_number_valid:
                continue

            self.steamreg.steam_finalize_authenticator_request(steam_client, mobguard_data, sms_code)

            ctr += 1

            mobguard_data['account_password'] = passwd
            self.save_attached_account(mobguard_data, login, passwd, number)
            if not self.autoreg.get():
                self.activate_steam_account(steam_client)
                self.remove_intentory_privacy(steam_client)
            self.log_box.insert(END, 'Guard успешно привязан: ' + login)

    def accounts_generator(self):
        ctr = 0
        new_accounts_amount = self.new_accounts_amount.get()
        while ctr < new_accounts_amount:
            new_accounts = []
            for _ in range(self.accounts_per_number.get()):
                self.status_bar.set('Создаю аккаунт, решаю капчу...')
                login, passwd = self.steamreg.create_account(self.rucaptcha_api_key.get())
                new_accounts.append((login, passwd))
                self.log_box.insert(END, 'Аккаунт зарегистрирован: %s %s' % (login, passwd))
                ctr += 1
                if ctr == new_accounts_amount:
                    break
            for login, passwd in new_accounts:
                yield login, passwd

    def registrate_account(self):
        login, passwd = self.steamreg.create_account(self.rucaptcha_api_key.get())
        with lock:
            self.log_box.insert(END, 'Аккаунт зарегистрирован: %s %s' % (login, passwd))
            logger.info('account data: %s %s', login, passwd)
            self.save_unattached_account(login, passwd)
        steam_client = SteamClient()
        while True:
            try:
                steam_client.login(login, passwd)
                break
            except AttributeError:
                time.sleep(3)
        self.activate_steam_account(steam_client)
        self.remove_intentory_privacy(steam_client)

    def get_new_number(self, sms_service, tzid):
        if tzid:
            sms_service.set_operation_ok(tzid)
            sms_service.used_codes.clear()
        ctr = 0
        is_repeated = False
        self.status_bar.set('Запрашиваю новый номер...')
        tzid = sms_service.request_new_number()
        number = sms_service.get_number(tzid)
        self.log_box.insert(END, 'Новый номер: ' + number)
        return tzid, number, is_repeated, ctr

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
        resp = requests.post('http://rucaptcha.com/in.php',
                             data={'key': self.rucaptcha_api_key.get()})
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

    def save_attached_account(self, mobguard_data, login, passwd, number):
        steamid = mobguard_data['Session']['SteamID']
        accounts_dir = 'new_accounts' if self.autoreg.get() else 'old_accounts'
        txt_path = os.path.join(accounts_dir, login + '.txt')
        mafile_path = os.path.join(accounts_dir, login + '.maFile')

        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write('{}:{}\nДата привязки Guard: {}\nНомер: {}\nSteamID: {}'.format(
                     login, passwd, str(datetime.date.today()), number, steamid))
        with open('accounts_attached.txt', 'a+') as f:
            f.write('%s:%s\n' % (login, passwd))

        if self.import_mafile.get():
            mafile_path = os.path.join(os.path.dirname(self.manifest_path), login + '.maFile')
            data = {
                "encryption_iv": None,
                "encryption_salt": None,
                "filename": login + '.maFile',
                "steamid": int(steamid)
            }
            self.manifest_data["entries"].append(data)
            with open(self.manifest_path, 'w') as f:
                json.dump(self.manifest_data, f)

        with open(mafile_path, 'w') as f:
            json.dump(mobguard_data, f)

    def save_unattached_account(self, login, passwd):
        with open('accounts_unattached.txt', 'a+') as f:
            f.write('%s:%s\n' % (login, passwd))


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
        self.accounts = []
        try:
            with open(accounts_path, 'r') as f:
                for acc_item in f.readlines():
                    split_char = ':' if ':' in acc_item else ','
                    acc_data = acc_item.rstrip().split(split_char)
                    self.accounts.append(acc_data)
            self.accounts_path = accounts_path
        except (EnvironmentError, TypeError) as err:
            # showwarning("Ошибка", "Не удалось загрузить: {0}:\n{1}".format(
            #                        accounts_path, err), parent=self.parent)
            pass

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
        except (EnvironmentError, TypeError) as err:
            # showwarning("Ошибка", "Не удалось загрузить: {0}:\n{1}".format(
            #                        manifest_path, err), parent=self.parent)
            pass

    @staticmethod
    def activate_steam_account(steam_client):
        url = 'https://steamcommunity.com/profiles/{}/edit'.format(steam_client.steamid)
        data = {
            'sessionID': steam_client.get_session_id(),
            'type': 'profileSave',
            'personaName': steam_client.login_name,
            'summary': 'No information given.',
            'primary_group_steamid': '0'
        }
        steam_client.session.post(url, data=data)

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
        steam_client.session.post(url, data=data)

    def app_quit(self, *ignore):
        with open('database/userdata.txt', 'w') as f:
            json.dump(self.userdata, f)

        self.parent.destroy()

if __name__ == '__main__':
    logging.getLogger("requests").setLevel(logging.ERROR)
    logger = logging.getLogger()
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    handler = logging.FileHandler('database/logs.txt', 'w', encoding='utf-8')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    def uncaught_exceptions_handler(type, value, tb):
        logger.critical("Uncaught exception: {0} {1} {2}".format(type, value, traceback.format_tb(tb)))
    sys.excepthook = uncaught_exceptions_handler

    root = Tk()
    window = MainWindow(root)
    root.iconbitmap('database/app.ico')
    root.title('Steam Auto Authenticator v0.3')
    root.protocol("WM_DELETE_WINDOW", window.app_quit)
    root.mainloop()
