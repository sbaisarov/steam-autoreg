# TODO: remove warning while quitting the app

from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import showwarning
import logging
import os
import sys
import datetime
import uuid
import json
import time
import traceback
import threading

import requests
from execjs._external_runtime import ExternalRuntime

from steampy.client import SteamClient
from steampy.guard import generate_one_time_code
from sms_services import *
from steamreg import *


def uncaught_exceptions_handler(type, value, tb):
    logger.critical("Uncaught exception: {0} {1}\n{2}".format(type, value, ''.join(traceback.format_tb(tb))))


logger = logging.getLogger('__main__')

for dir_name in ('новые_аккаунты', 'загруженные_аккаунты'):
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

if not os.path.exists('database/userdata.txt'):
    with open('database/userdata.txt', 'w') as f:
        f.write('{}')

sys.excepthook = uncaught_exceptions_handler
steamreg = SteamRegger()
with open("database/interface_states.json", "r") as f:
    STATES = json.load(f)


class MainWindow:

    def __init__(self, parent):
        self.parent = parent
        self.frame = Frame(self.parent)
        with open('database/userdata.txt', 'r') as f:
            self.userdata = json.load(f)

        success = self.authorize_user()
        if not success:
            self.deploy_activation_widgets(self.frame)
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
        self.temp_mail = IntVar()
        self.private_email_boxes = IntVar()
        self.email_domain = StringVar()
        self.status_bar = StringVar()
        self.reg_type = StringVar()
        self.reg_type.set("client")

        self.menubar = Menu(parent)
        parent['menu'] = self.menubar

        self.accounts_per_number_label = Label(self.frame, text='Количество аккаунтов на 1 номер:')
        self.accounts_per_number_entry = Entry(self.frame, textvariable=self.accounts_per_number,
                                               width=2, disabledforeground='#808080')
        self.onlinesim_apikey_label = Label(self.frame, text='onlinesim api key:')
        self.onlinesim_apikey_entry = Entry(self.frame, textvariable=self.onlinesim_api_key, disabledforeground='#808080')

        self.new_accounts_amount_label = Label(self.frame, text='Количество аккаунтов для регистрации:')
        self.new_accounts_amount_entry = Entry(self.frame, textvariable=self.new_accounts_amount, width=4,  disabledforeground='#808080')
        self.rucaptcha_apikey_label = Label(self.frame, text='rucaptcha api key:')
        self.rucaptcha_apikey_entry = Entry(self.frame, textvariable=self.rucaptcha_api_key, disabledforeground='#808080')

        self.email_domain_label = Label(self.frame, text='Домен для email (по усмотрению, без @):')
        self.email_domain_entry = Entry(self.frame, textvariable=self.email_domain, disabledforeground='#808080')
        self.reg_type_label = Label(self.frame, text='Способ регистрации:')
        self.client_option = Radiobutton(self.frame, text="Клиент", variable=self.reg_type, value="client")
        self.web_option = Radiobutton(self.frame, text="Веб", variable=self.reg_type, value="web")

        tools_frame = Frame(self.parent)
        self.tools_label = Label(tools_frame, text='Инструменты:')
        self.options_label = Label(tools_frame, text='Опции:')
        self.autoreg_checkbutton = Checkbutton(tools_frame, text='Создавать новые аккаунты',
                                               variable=self.autoreg, command=self.set_states,
                                               disabledforeground='#808080')
        self.temp_mail_checkbutton = Checkbutton(tools_frame, text='Использовать временные почты',
                                                 variable=self.temp_mail, command=self.set_states,
                                                 disabledforeground='#808080')
        self.mafile_checkbutton = Checkbutton(tools_frame, text='Импортировать maFile в SDA',
                                              variable=self.import_mafile, command=self.set_states,
                                              disabledforeground='#808080')
        self.mobile_bind_checkbutton = Checkbutton(tools_frame, text='Привязывать Mobile Guard',
                                                   variable=self.mobile_bind, command=self.set_states,
                                                   disabledforeground='#808080')
        self.fold_accounts_checkbutton = Checkbutton(tools_frame, text='Раскладывать по папкам',
                                                     variable=self.fold_accounts, disabledforeground='#808080')


        self.start_button = Button(tools_frame, text='Начать', command=self.start_process,
                                   bg='#CEC8C8', relief=GROOVE, width=50)
        tools_frame.grid(row=1, column=0, pady=5)

        log_frame = Frame(self.parent)
        self.log_label = Label(log_frame, text='Логи:')
        self.scrollbar = Scrollbar(log_frame, orient=VERTICAL)
        self.log_box = Listbox(log_frame, yscrollcommand=self.scrollbar.set)
        self.log_box.bind('<Enter>', self.freeze_log)
        self.log_box.bind('<Leave>', self.unfreeze_log)
        self.log_frozen = False
        self.scrollbar["command"] = self.log_box.yview
        self.scrollbar.bind('<Enter>', self.freeze_log)
        self.scrollbar.bind('<Leave>', self.unfreeze_log)

        self.frame.grid(row=0, column=0, sticky=W)
        log_frame.columnconfigure(0, weight=999)
        log_frame.columnconfigure(1, weight=1)
        log_frame.grid(row=2, column=0, sticky=NSEW)

        self.status_bar_label = Label(log_frame, anchor=W, text='Готов...', textvariable=self.status_bar)
        self.caption_label = Label(log_frame, text='by Shamanovsky')

        if self.userdata:
            self.set_attributes()

        self.pack_widgets()

    def set_states(self):
        for checkbutton_name, configs in sorted(STATES.items(), key=lambda item: item[1]["priority"]):
            flag = self.__getattribute__(checkbutton_name).get()
            for entry, state in configs.get("entries", {}).items():
                state = self.adjust_state(flag, state)
                self.__getattribute__(entry).configure(state=state)
            for menu_item, states in configs.get("menubar", {}).items():
                for menu_index, state in states.items():
                    state = self.adjust_state(flag, state)
                    self.__getattribute__(menu_item).entryconfig(menu_index, state=state)
            for checkbutton_attr, state in configs.get("checkbuttons", {}).items():
                state = self.adjust_state(flag, state)
                self.__getattribute__(checkbutton_attr).configure(state=state)

    @staticmethod
    def adjust_state(flag, state):
        reversed_states = {NORMAL: DISABLED, DISABLED: NORMAL}
        if not flag:
            state = reversed_states[state]
        return state

    def set_attributes(self):
        for attr_name, value in self.userdata.items():
            if attr_name == 'manifest_path':
                self.load_manifest(value)
            else:
                attribute = self.__getattribute__(attr_name)
                attribute.set(value)

    def pack_widgets(self):
        self.load_menu = Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Загрузить...", menu=self.load_menu)
        self.load_menu.add_command(label="Свои аккаунты", command=self.accounts_open)
        self.load_menu.add_command(label="Свои почты", command=self.email_boxes_open)
        self.load_menu.add_command(label="SDA Manifest", command=self.manifest_open)

        self.onlinesim_apikey_label.grid(row=0, column=0, pady=5, sticky=W)
        self.onlinesim_apikey_entry.grid(row=0, column=1, pady=5, padx=5, sticky=W)

        self.rucaptcha_apikey_label.grid(row=1, column=0, pady=5, sticky=W)
        self.rucaptcha_apikey_entry.grid(row=1, column=1, pady=5, padx=5, sticky=W)

        self.new_accounts_amount_label.grid(row=2, column=0, pady=5, sticky=W)
        self.new_accounts_amount_entry.grid(row=2, column=1, pady=5, padx=5, sticky=W)

        self.accounts_per_number_label.grid(row=3, column=0, pady=5, sticky=W)
        self.accounts_per_number_entry.grid(row=3, column=1, pady=5, padx=5, sticky=W)

        self.reg_type_label.grid(row=4, column=0, pady=3, sticky=W)
        self.web_option.grid(row=5, column=0, pady=3, sticky=W)
        self.client_option.grid(row=5, column=0, pady=3, sticky=E)

        # self.email_domain_label.grid(row=4, column=0, pady=5, sticky=W)
        # self.email_domain_entry.grid(row=4, column=1, pady=5, padx=5, sticky=W)

        self.tools_label.grid(row=0, column=0, pady=3, sticky=W)
        self.options_label.grid(row=2, column=0, pady=3, sticky=W)

        self.autoreg_checkbutton.grid(row=1, column=0, sticky=W)
        # self.private_email_boxes_checkbutton.grid(row=3, column=0, pady=1, sticky=W)
        self.temp_mail_checkbutton.grid(row=3, column=0, pady=1, sticky=W)

        self.mobile_bind_checkbutton.grid(row=1, column=1, pady=1, sticky=W)
        self.mafile_checkbutton.grid(row=3, column=1, pady=1)
        self.fold_accounts_checkbutton.grid(row=4, column=1, pady=1, sticky=W)

        self.start_button.grid(row=5, pady=10, columnspan=2)
        self.log_label.grid(row=0, column=0, pady=5, sticky=W)
        self.log_box.grid(row=1, column=0, sticky=NSEW)
        self.scrollbar.grid(row=1, column=1, sticky=NS)
        self.status_bar_label.grid(row=2, column=0, columnspan=2, sticky=W, pady=5)
        self.caption_label.grid(row=2, column=0, sticky=E)
        self.set_states()

    def add_log(self, message):
        self.log_box.insert(END, message)
        if not self.log_frozen:
            self.log_box.yview(END)

    def freeze_log(self, *ignore):
        self.log_frozen = True

    def unfreeze_log(self, *ignore):
        self.log_frozen = False

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

        if self.autoreg.get():
            if self.reg_type == 'web':
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
        reg_type = self.reg_type.get()
        new_accounts_amount = self.new_accounts_amount.get()
        if reg_type == 'web':
            self.init_threads(new_accounts_amount)
        else:
            self.registrate_client(new_accounts_amount)

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
        reg_type = self.reg_type.get()
        while ctr < new_accounts_amount:
            remainder = new_accounts_amount - ctr
            if remainder < accounts_per_number:
                accounts_per_number = remainder
            if reg_type == 'web':
                new_accounts = self.init_threads(accounts_per_number, threads_amount=accounts_per_number)
            elif reg_type == 'client':
                new_accounts = self.registrate_client(accounts_per_number)
            ctr += accounts_per_number
            yield new_accounts

    def init_threads(self, accs_amount, threads_amount=20):
        self.status_bar.set('Создаю аккаунты, решаю капчи...')
        threads = []
        new_accounts = []
        for _ in range(threads_amount):
            t = RegistrationThread(self, accs_amount, new_accounts)
            t.start()
            threads.append(t)
        for thread in threads:
            thread.join()
            if thread.error:
                error_origin, error_text = thread.error
                showwarning("Ошибка %s" % error_origin, error_text)
                return
        RegistrationThread.counter = 0
        return new_accounts

    def registrate_client(self, amount):
        self.status_bar.set('Создаю аккаунты...')
        result = steamreg.create_accounts_client(amount)
        for login, passwd in result:
            self.add_log('Аккаунт зарегистрирован: %s %s' % (login, passwd))
        return result

    def authorize_user(self):
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
        license_key_label = Label(self.frame, text='Введите ключ активации программы:')
        license_key_label.grid(row=0, column=0, pady=5, sticky=W)
        self.license_key_entry = Entry(frame)
        self.license_key_entry.grid(row=0, column=1, pady=5, padx=5, sticky=W)
        login_label = Label(self.frame, text='Ваш логин:')
        login_label.grid(row=1, column=0, pady=5, sticky=W)
        self.login_entry = Entry(frame)
        self.login_entry.grid(row=1, column=1, pady=5, padx=5, sticky=W)
        check_license_bttn = Button(self.frame, text='Проверить лицензию',
                                    command=lambda: self.check_license(frame),
                                    relief=GROOVE)
        check_license_bttn.grid(sticky=W, padx=20, pady=5)
        frame.grid(row=0, column=0)

    def check_rucaptcha_key(self):
        if not self.rucaptcha_api_key.get():
            raise RuCaptchaError('"Не указан api ключ RuCaptcha"')
            return

        resp = requests.post('http://rucaptcha.com/res.php',
                             data={'key': self.rucaptcha_api_key.get().strip(),
                                   'action': 'getbalance'})
        logger.info(resp.text)
        if 'ERROR_ZERO_BALANCE' in resp.text:
            raise RuCaptchaError('На счету нулевой баланс')
        elif 'ERROR_WRONG_USER_KEY' in resp.text or 'ERROR_KEY_DOES_NOT_EXIST' in resp.text:
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
        dir_ = (os.path.dirname(self.email_boxes_path)
                if self.email_boxes_path is not None else '.')
        email_boxes_path = askopenfilename(
                    title='Email адреса',
                    initialdir=dir_,
                    filetypes=[('Text file', '*.txt')],
                    defaultextension='.txt', parent=self.parent)
        if email_boxes_path:
            return self.load_emails(email_boxes_path)

    def load_emails(self, email_boxes_path):
        try:
            with open(email_boxes_path, 'r') as f:
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

        try:
            if ExternalRuntime.process is not None:
                ExternalRuntime.process.kill()
        except:
            showwarning('Внимание!',
                        'Для корректной работы программы введите в cmd.exe команду: pip uninstall pyexecjs')
        self.parent.destroy()


class RegistrationThread(threading.Thread):

    counter = 0
    lock = threading.Lock()
    email_lock = threading.Lock()

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
        login, passwd = steamreg.create_account_web(self.window.rucaptcha_api_key.get().strip(),
                                                    thread_lock=RegistrationThread.email_lock)
        logger.info('Аккаунт: %s:%s', login, passwd)
        self.window.add_log('Аккаунт зарегистрирован: %s %s' % (login, passwd))

        with RegistrationThread.lock:
            if not self.window.mobile_bind.get():
                self.save_unattached_account(login, passwd)
        steam_client = SteamClient()
        while True:
            try:
                with RegistrationThread.lock:
                    time.sleep(3)
                    steam_client.login(login, passwd)
                break
            except AttributeError as err:
                logger.error(err)
                time.sleep(3)

        steamreg.activate_account(steam_client)
        steamreg.remove_intentory_privacy(steam_client)
        if self.result is not None:
            self.result.append((login, passwd))

    def save_unattached_account(self, login, passwd):
        with open('accounts.txt', 'a+') as f:
            f.write('%s:%s\n' % (login, passwd))


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
            offer_link = steamreg.fetch_tradeoffer_link(steam_client)
            self.save_attached_account(mobguard_data, login, passwd, number, offer_link)
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

    def save_attached_account(self, mobguard_data, login, passwd, number, offer_link):
        if self.window.mobile_bind.get():
            if self.window.autoreg.get():
                accounts_dir = 'новые_аккаунты'
                if self.window.fold_accounts.get():
                    accounts_dir = os.path.join(accounts_dir, login)
                    os.makedirs(accounts_dir)
            else:
                accounts_dir = 'загруженные_аккаунты'

        steamid = mobguard_data['Session']['SteamID']
        txt_path = os.path.join(accounts_dir, login + '.txt')
        mafile_path = os.path.join(accounts_dir, login + '.maFile')
        binding_date = datetime.date.today()
        email = steamreg.email
        revocation_code = mobguard_data['revocation_code']
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write('{login}:{passwd}\nДата привязки Guard: {binding_date}\nНомер: {number}\n'
                    'SteamID: {steamid}\nEmail: {email}\nRCODE: {revocation_code}\nТрейд ссылка: {offer_link}'.format(**locals()))

        with open('accounts_guard.txt', 'a+') as f:
            f.write('%s:%s\n' % (login, passwd))

        if self.window.import_mafile.get():
            sda_path = os.path.join(os.path.dirname(self.window.manifest_path), login + '.maFile')
            data = {
                "encryption_iv": None,
                "encryption_salt": None,
                "filename": login + '.maFile',
                "steamid": int(steamid)
            }
            self.window.manifest_data["entries"].append(data)
            with open(self.window.manifest_path, 'w') as f1, open(sda_path, 'w') as f2:
                json.dump(self.window.manifest_data, f1)
                json.dump(mobguard_data, f2, separators=(',', ':'))

        with open(mafile_path, 'w') as f:
            json.dump(mobguard_data, f, separators=(',', ':'))

    def log_wrapper(self, login):
        def insert_log(text):
            self.window.add_log('%s (%s)' % (text, login))
        return insert_log


root = Tk()
window = MainWindow(root)
root.iconbitmap('database/app.ico')
root.title('Steam Auto Authenticator v0.71')
root.protocol("WM_DELETE_WINDOW", window.app_quit)
root.mainloop()
