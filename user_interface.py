from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import showwarning
import datetime
import os
import traceback
import threading
import asyncio
import enum
from collections import namedtuple
from queue import Queue, Empty
from proxybroker import Broker
# import wmi
import hashlib

from sms_services import *
from steamreg import *


logger = logging.getLogger('__main__')

for dir_name in ('новые_аккаунты', 'загруженные_аккаунты'):
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

if not os.path.exists('database/userdata.txt'):
    with open('database/userdata.txt', 'w') as f:
        f.write('{}')

steamreg = SteamRegger()

with open("database/interface_states.json", "r") as f:
    STATES = json.load(f)

loop = asyncio.get_event_loop()
Account = namedtuple("Account", ['login', 'password', 'email', 'email_password'])


class Proxy(enum.IntEnum):
    Local = 0
    Public = 1
    Url = 2
    File = 3


class MainWindow:

    def __init__(self, parent):
        self.parent = parent
        self.frame = Frame(self.parent)
        self.is_running = False
        with open('database/userdata.txt', 'r') as f:
            self.userdata = json.load(f)

        success = self.authorize_user()
        if not success:
            self.deploy_activation_widgets(self.frame)
            return

        self.queue = asyncio.Queue(loop=loop)
        self.accounts = Queue()
        self.reg_proxies = Queue()
        self.bind_proxies = Queue()

        self.proxy_broker = None

        self.manifest_path = ''
        self.accounts_path = ''
        self.email_boxes_path = ''
        self.proxy_path = ''
        self.proxy_urls_path = ''

        self.proxy_data = []
        self.proxy_urls = []
        self.privacy_settings = {}
        self.email_boxes_data = []
        self.old_accounts = []
        self.manifest_data = None

        self.autoreg = IntVar()
        self.import_mafile = IntVar()
        self.mobile_bind = IntVar()
        self.fold_accounts = IntVar()
        self.temp_mail = IntVar()

        self.onlinesim_api_key = StringVar()
        self.rucaptcha_api_key = StringVar()
        self.new_accounts_amount = IntVar()
        self.accounts_per_number = IntVar()
        self.amount_of_binders = IntVar()
        self.amount_of_binders.set(1)
        self.private_email_boxes = IntVar()
        self.status_bar = StringVar()
        self.country_code = StringVar()
        self.country_code.set('7')
        self.proxy_type = IntVar()
        self.use_local_ip = IntVar()
        self.pass_login_captcha = IntVar()

        self.accounts_registrated = StringVar()
        self.accounts_registrated.set("Аккаунтов зарегистрировано: 0")

        self.menubar = Menu(parent)
        parent['menu'] = self.menubar

        self.accounts_per_number_label = Label(self.frame, text='Количество аккаунтов на 1 номер:')
        self.accounts_per_number_entry = Entry(self.frame, textvariable=self.accounts_per_number,
                                               width=2, disabledforeground='#808080')
        self.onlinesim_apikey_label = Label(self.frame, text='onlinesim api key:')
        self.onlinesim_apikey_entry = Entry(self.frame, textvariable=self.onlinesim_api_key, disabledforeground='#808080', width=25)

        self.new_accounts_amount_label = Label(self.frame, text='Количество аккаунтов для регистрации:')
        self.new_accounts_amount_entry = Entry(self.frame, textvariable=self.new_accounts_amount, width=4,
                                               disabledforeground='#808080')
        self.rucaptcha_apikey_label = Label(self.frame, text='rucaptcha api key:')
        self.rucaptcha_apikey_entry = Entry(self.frame, textvariable=self.rucaptcha_api_key,
                                            disabledforeground='#808080', width=25)

        self.country_code_label = Label(self.frame, text='Страна номера:')
        self.russia_option = Radiobutton(self.frame, text="Россия", variable=self.country_code, value="7")
        self.china_option = Radiobutton(self.frame, text="Китай", variable=self.country_code, value="86")
        self.nigeria_option = Radiobutton(self.frame, text="Нигерия", variable=self.country_code, value="234")
        self.kotdivuar_option = Radiobutton(self.frame, text="Кот д'ивуар", variable=self.country_code, value="225")
        self.ukraine_option = Radiobutton(self.frame, text="Украина", variable=self.country_code, value="380")
        self.kazakhstan_option = Radiobutton(self.frame, text="Казахстан", variable=self.country_code, value="77")
        self.egypt_option = Radiobutton(self.frame, text="Египет", variable=self.country_code, value="20")

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
        self.amount_of_binders_label = Label(tools_frame, text='Количество потоков:')
        self.amount_of_binders_field = Entry(tools_frame, textvariable=self.amount_of_binders,
                                             disabledforeground='#808080', width=2)

        self.start_button = Button(tools_frame, text='Начать', command=self.start_process,
                                   bg='#CEC8C8', relief=GROOVE, width=50)
        tools_frame.grid(row=1, column=0, pady=5)

        log_frame = Frame(self.parent)
        self.log_label = Label(log_frame, text='Логи:')
        self.scrollbar = Scrollbar(log_frame, orient=VERTICAL)
        self.scrollbar_x = Scrollbar(log_frame, orient=HORIZONTAL)
        self.log_box = Listbox(log_frame, yscrollcommand=self.scrollbar.set, xscrollcommand=self.scrollbar_x.set)
        self.log_box.bind('<Enter>', self.freeze_log)
        self.log_box.bind('<Leave>', self.unfreeze_log)
        self.log_frozen = False
        self.scrollbar["command"] = self.log_box.yview
        self.scrollbar.bind('<Enter>', self.freeze_log)
        self.scrollbar.bind('<Leave>', self.unfreeze_log)

        self.scrollbar_x["command"] = self.log_box.xview
        self.scrollbar_x.bind('<Enter>', self.freeze_log)
        self.scrollbar_x.bind('<Leave>', self.unfreeze_log)

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
            if 'path' in attr_name:
                self.load_manifest(value)
            else:
                try:
                    attribute = self.__getattribute__(attr_name)
                    attribute.set(value)
                except AttributeError:
                    continue

    def pack_widgets(self):
        self.load_menu = Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Загрузить...", menu=self.load_menu)
        self.load_menu.add_command(label="Свои аккаунты", command=self.accounts_open)
        self.load_menu.add_command(label="Свои почты", command=self.email_boxes_open)
        self.load_menu.add_command(label="SDA Manifest", command=self.manifest_open)

        self.proxy_menu = Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Настроить прокси", command=self.deploy_proxy_widget)

        self.menubar.add_cascade(label="Открыть статистику", command=self.deploy_stats_window)

        self.onlinesim_apikey_label.grid(row=0, column=0, pady=5, sticky=W)
        self.onlinesim_apikey_entry.grid(row=0, column=1, pady=5, padx=5, sticky=W)

        self.rucaptcha_apikey_label.grid(row=1, column=0, pady=5, sticky=W)
        self.rucaptcha_apikey_entry.grid(row=1, column=1, pady=5, padx=5, sticky=W)

        self.rucaptcha_apikey_entry.grid(row=1, column=1, pady=5, padx=5, sticky=W)

        self.new_accounts_amount_label.grid(row=2, column=0, pady=5, sticky=W)
        self.new_accounts_amount_entry.grid(row=2, column=1, pady=5, padx=5, sticky=W)

        self.accounts_per_number_label.grid(row=3, column=0, pady=5, sticky=W)
        self.accounts_per_number_entry.grid(row=3, column=1, pady=5, padx=5, sticky=W)

        self.country_code_label.grid(row=4, column=0, pady=3, sticky=W)
        self.russia_option.grid(row=5, padx=3, column=0, pady=3, sticky=W)
        self.ukraine_option.grid(row=5, column=0, pady=3, sticky=E, padx=47)
        self.egypt_option.grid(row=5, column=1, pady=3, sticky=W)
        self.nigeria_option.grid(row=5, column=1, pady=3, sticky=E)
        self.china_option.grid(row=6, column=0, pady=3, padx=3, sticky=W)
        self.kazakhstan_option.grid(row=6, column=0, pady=3, padx=40, sticky=E)
        self.kotdivuar_option.grid(row=6, column=1, pady=3, sticky=W)

        self.tools_label.grid(row=0, column=0, pady=3, sticky=W)
        self.autoreg_checkbutton.grid(row=1, column=0, sticky=W)
        self.mobile_bind_checkbutton.grid(row=1, column=1, pady=1, sticky=W)
        self.options_label.grid(row=2, column=0, pady=3, sticky=W)

        self.temp_mail_checkbutton.grid(row=3, column=0, pady=1, sticky=W)
        self.mafile_checkbutton.grid(row=3, column=1, pady=1)
        self.fold_accounts_checkbutton.grid(row=4, column=1, pady=1, sticky=W)
        self.amount_of_binders_label.grid(row=5, column=1, pady=1, sticky=W)
        self.amount_of_binders_field.grid(row=5, column=1, pady=1, padx=45, sticky=E)

        self.start_button.grid(row=6, pady=10, columnspan=2)
        self.log_label.grid(row=0, column=0, pady=5, sticky=W)
        self.log_box.grid(row=1, column=0, sticky=NSEW)
        self.scrollbar.grid(row=1, column=1, sticky=NS)
        self.scrollbar_x.grid(row=2, column=0, sticky=EW)
        self.status_bar_label.grid(row=3, column=0, columnspan=2, sticky=W, pady=5)
        self.caption_label.grid(row=3, column=0, sticky=E)
        self.set_states()

    def deploy_stats_window(self):
        top = Toplevel(master=self.frame)
        top.title("Статистика")
        top.iconbitmap('database/stats.ico')
        top.geometry('550x355')

        lbl = Label(top, textvariable=self.accounts_registrated)
        lbl.grid(row=0, column=0, padx=5, pady=10, sticky=W)

        self.accounts_binded = StringVar()
        lbl2 = Label(top, textvariable=self.accounts_binded)
        lbl2.grid(row=1, column=0, padx=5, pady=10, sticky=W)
        self.accounts_binded.set("Аккаунтов привязано: 0")

        self.captchas_resolved = StringVar()
        lbl3 = Label(top, textvariable=self.captchas_resolved)
        lbl3.grid(row=2, column=0, padx=5, pady=10, sticky=W)
        self.captchas_resolved.set("Капч решено успешно: 0")

    def add_log(self, message):
        self.log_box.insert(END, message)
        if not self.log_frozen:
            self.log_box.yview(END)

    def freeze_log(self, *ignore):
        self.log_frozen = True

    def unfreeze_log(self, *ignore):
        self.log_frozen = False

    def run_process(self):
        self.save_input()
        new_accounts_amount = self.new_accounts_amount.get()
        onlinesim_api_key = self.onlinesim_api_key.get()
        reg_threads = []
        bind_threads = []
        if self.mobile_bind.get():
            sms_service = OnlineSimApi(onlinesim_api_key)
            for _ in range(self.amount_of_binders.get()):
                t = Binder(self, sms_service, self.accounts_per_number.get())
                t.start()
                bind_threads.append(t)
        if self.autoreg.get():
            reg_threads = self.init_threads(new_accounts_amount)
        else:
            self.put_from_text_file()

        for thread in reg_threads:
            thread.join()
        RegistrationThread.is_alive = False

        for thread in bind_threads:
            thread.join()

        self.is_running = False
        self.status_bar.set('Готов...')

    def check_input(self):
        if not self.manifest_path and self.import_mafile.get():
            showwarning("Ошибка", "Не указан путь к manifest файлу Steam Desktop Authenticator",
                        parent=self.parent)
            return False

        if not self.proxy_path and self.proxy_type.get() == Proxy.File:
            showwarning("Ошибка", "Не указан путь к файлу с прокси",
                        parent=self.parent)
            return False

        if not self.proxy_urls_path and self.proxy_type.get() == Proxy.Url:
            showwarning("Ошибка", "Не указан путь к файлу с ссылками на списки прокси",
                        parent=self.parent)
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

            try:
                if not 0 < self.amount_of_binders.get() <= 10:
                    raise ValueError
            except (TclError, ValueError):
                showwarning("Ошибка", "Введите корректное число потоков для привязки меньше 10",
                            parent=self.parent)
                return False

            onlinesim_api_key = self.onlinesim_api_key.get()
            if not onlinesim_api_key:
                showwarning("Ошибка", "Не указан api ключ для onlinesim.ru", parent=self.parent)
                return False

            if not self.accounts_path and not self.autoreg.get():
                showwarning("Ошибка", "Не указан путь к файлу с данными от аккаунтов. "
                                      "Если у вас нет своих аккаунтов, то поставьте галочку 'Создавать новые аккаунты'",
                            parent=self.parent)
                return False

        return True

    def save_input(self):
        for field, value in self.__dict__.items():
            if field in ('status_bar', 'license'):
                continue
            if issubclass(value.__class__, Variable) or 'path' in field:
                try:
                    value = value.get()
                except AttributeError:
                    pass
                self.userdata[field] = value

    def init_threads(self, threads_amount=20):
        RegistrationThread.left = self.new_accounts_amount.get()
        threads = []
        if threads_amount > 20:
            threads_amount = 20
        for _ in range(threads_amount):
            t = RegistrationThread(self)
            t.start()
            threads.append(t)
        return threads

    def authorize_user(self):
        if os.path.exists('database/key.txt'):
            with open('database/key.txt', 'r') as f:
                user_data = json.load(f)
            url = 'http%s://shamanovski.pythonanywhere.com/'
            data = {
                'login': user_data['login'],
                'key': user_data['key'],
                'uid': self.get_node()
            }
            reg_proxies = {
                'https': 'http://195.242.219.137:5000',
                'http': 'http://195.242.219.137:5000'
            }

            try:
                resp = requests.post(url % 's', data=data, timeout=10, attempts=1).json()
            except ConnectionError:
                resp = requests.post(url % '', data=data, timeout=10, reg_proxies=reg_proxies).json()
        else:
            return False

        return resp['success_x001']

    def check_license(self):
        key, login = self.license_key_entry.get(), self.login_entry.get()
        if not all((key, login)):
            showwarning('Ошибка', 'Заполните все поля', parent=self.parent)
            return
        url = 'http%s://shamanovski.pythonanywhere.com/'
        data = {
            'login': login,
            'key': key,
            'uid': self.get_node()
        }
        reg_proxies = {
            'https': 'http://195.242.219.137:5000',
            'http': 'http://195.242.219.137:5000'
        }

        try:
            resp = requests.post(url % 's', data=data, timeout=10, attempts=1).json()
        except ConnectionError:
            resp = requests.post(url % '', data=data, timeout=10, reg_proxies=reg_proxies).json()

        if not resp['success_x001']:
            showwarning('Ошибка', 'Неверный ключ либо попытка активации с неавторизованного устройства',
                        parent=self.parent)
            return

        with open('database/key.txt', 'w') as f:
            json.dump({'login': login, 'key': key}, f)

        top = Toplevel(self.parent)
        top.title("Успешно!")
        top.geometry('230x50')
        msg = 'Программа активирована. Приятного пользования!'
        msg = Message(top, text=msg, aspect=500)
        msg.grid()

        self.frame.destroy()

        self.__init__(self.parent)

    def deploy_activation_widgets(self, frame):
        self.license = StringVar()
        license_key_label = Label(self.frame, text='Введите ключ активации программы:')
        license_key_label.grid(row=0, column=0, pady=5, sticky=W)
        self.license_key_entry = Entry(frame)
        self.license_key_entry.grid(row=0, column=1, pady=5, padx=5, sticky=W)
        login_label = Label(self.frame, text='Ваш логин (любой):')
        login_label.grid(row=1, column=0, pady=5, sticky=W)
        self.login_entry = Entry(frame)
        self.login_entry.grid(row=1, column=1, pady=5, padx=5, sticky=W)
        check_license_bttn = Button(self.frame, text='Проверить лицензию',
                                    command=self.check_license,
                                    relief=GROOVE)
        check_license_bttn.grid(sticky=W, padx=20, pady=5)
        frame.grid(row=0, column=0)

    async def produce_proxies(self):
        if not self.proxy_type.get():
            return
        pass_login_captcha = self.pass_login_captcha.get()
        while True:
            proxy = await self.queue.get()
            if proxy is None:
                return
            try:
                ban = steamreg.check_proxy_ban(proxy)
            except (ProxyError, ConnectionError, Timeout):
                self.add_log("Нестабильное соединение: %s" % (proxy if proxy else "local ip"))
                continue
            if ban and pass_login_captcha:
                self.add_log("%s: требуется решить капчу для авторизации в аккаунты"
                                    % (str(proxy).strip("<>") if proxy else "local ip"))
                continue

            self.reg_proxies.put(proxy)
            self.bind_proxies.put(proxy)

    def deploy_proxy_widget(self):
        def set_state():
            type = self.proxy_type.get()
            for widget in (load_proxy_list_bttn, load_proxy_bttn):
                state = NORMAL if widget.value == type else DISABLED
                widget.configure(state=state)

        top = Toplevel(master=self.frame)
        top.title("Настройка прокси")
        top.iconbitmap('database/proxy.ico')
        top.geometry('550x355')
        checkbttn = Checkbutton(top, text="Не использовать родной IP если есть прокси", variable=self.use_local_ip)
        checkbttn.grid(column=0, row=0, pady=5, sticky=W)

        checkbttn2 = Checkbutton(top, text="\nПропускать прокси с которыми требуется\nрешать капчи для авторизации",
                                 variable=self.pass_login_captcha)
        checkbttn2.grid(column=1, row=0, pady=5, sticky=W)

        lbl = Label(top, text="Тип проксирования:")
        lbl.grid(column=0, row=1, padx=5, pady=10, sticky=W)

        rbttn1 = Radiobutton(top, command=set_state, text="Искать публичные прокси", variable=self.proxy_type,
                             value=int(Proxy.Public))
        rbttn1.grid(column=0, row=2, padx=5, pady=5, sticky=W)

        rbttn2 = Radiobutton(top, command=set_state, text="Загрузить ссылки на страницы с прокси:",
                             variable=self.proxy_type, value=int(Proxy.Url))
        rbttn2.grid(column=0, row=3, padx=5, pady=5, sticky=W)

        load_proxy_list_bttn = Button(top, state=DISABLED, text="Загрузить", command=lambda: self.proxy_list_open(top),
                                      relief=GROOVE)
        load_proxy_list_bttn.grid(column=0, row=4, padx=10, pady=5, sticky=W)
        load_proxy_list_bttn.value = int(Proxy.Url)

        rbttn3 = Radiobutton(top, command=set_state, text="Загрузить свои прокси:", variable=self.proxy_type,
                             value=int(Proxy.File))
        rbttn3.grid(column=0, row=5, padx=5, pady=5, sticky=W)

        load_proxy_bttn = Button(top, state=DISABLED, text="Загрузить", command=lambda: self.proxy_open(top),
                                 relief=GROOVE)
        load_proxy_bttn.grid(column=0, row=6, padx=10, pady=5, sticky=W)
        load_proxy_bttn.value = int(Proxy.File)

        rbttn4 = Radiobutton(top, command=set_state, text="Не использовать прокси", variable=self.proxy_type, value=0)
        rbttn4.grid(column=0, row=7, padx=5, pady=5, sticky=W)

        confirm_bttn = Button(top, command=top.destroy, text="Подтвердить")
        confirm_bttn.grid(column=0, columnspan=2, row=8, padx=5, pady=5)

        for rbttn in (rbttn1, rbttn2, rbttn3, rbttn4):
            if self.proxy_type.get() == rbttn.config("value"):
                rbttn.select()
                break

        set_state()
        top.focus_set()

    def check_rucaptcha_key(self):
        if not self.rucaptcha_api_key.get():
            raise RuCaptchaError('Не указан api ключ RuCaptcha')

        resp = requests.post('http://rucaptcha.com/res.php',
                             data={'key': self.rucaptcha_api_key.get().strip(),
                                   'action': 'getbalance'})
        logger.info(resp.text)
        if 'ERROR_ZERO_BALANCE' in resp.text:
            raise RuCaptchaError('На счету нулевой баланс')
        elif 'ERROR_WRONG_USER_KEY' in resp.text or 'ERROR_KEY_DOES_NOT_EXIST' in resp.text:
            raise RuCaptchaError('Неправильно введен API ключ')

    def get_node(self):
        # hardware = wmi.WMI()
        # try:
        #     processor_id = hardware.Win32_Processor()[0].ProcessorId
        #     motherboard_id = hardware.Win32_MotherboardDevice()[0].qualifiers["UUID"].strip("{}")
        # except (AttributeError, KeyError, IndexError) as err:
        #     logger.info(err)
        #     showwarning("Не удалось авторизовать устройство. Обратитесь к разработчику.", parent=self.parent)
        #     return None
        #
        # return hashlib.md5((processor_id + motherboard_id).encode('utf-8')).hexdigest()
        return "motherboard"

    def start_process(self):
        if self.is_running:
            return
        if not self.check_input():
            return
        self.is_running = True
        t = threading.Thread(target=self.init_proxy_producing)
        t.daemon = True
        t.start()

        t = threading.Thread(target=self.run_process)
        t.daemon = True
        t.start()

    def init_proxy_producing(self):
        proxy_type = self.proxy_type.get()
        if not self.use_local_ip.get() or proxy_type == Proxy.Local:
            self.reg_proxies.put(None)
            self.bind_proxies.put(None)
        if proxy_type == Proxy.Local:
            return
        providers = None
        if proxy_type == Proxy.Url:
            providers = self.proxy_urls
        self.proxy_broker = Broker(queue=self.queue, loop=loop, providers=providers)

        types = [('HTTP', ('Anonymous', 'High')), 'HTTPS', 'SOCKS4', 'SOCKS5']
        data = None
        if proxy_type == Proxy.File:
            with open(self.proxy_path) as f:
                data = f.read()
        asyncio.ensure_future(self.proxy_broker.find(
            data=data, types=types), loop=loop)
        self.status_bar.set("Чекаю прокси...")
        loop.run_until_complete(self.produce_proxies())
        loop.close()
        self.status_bar.set("")
        self.add_log("Закончил чекинг прокси")

    def accounts_open(self):
        dir = (os.path.dirname(self.accounts_path)
               if self.accounts_path is not None else '.')
        accounts_path = askopenfilename(
                    title='логин:пасс аккаунтов',
                    initialdir=dir,
                    filetypes=[('Text file', '*.txt')],
                    defaultextension='.txt', parent=self.parent)

        self.accounts_path = self.load_file(accounts_path, self.old_accounts, r"[\d\w]+:.+\n")

    def put_from_text_file(self):
        for item in self.old_accounts:
            login, password = item.split(':')[:2]
            account = Account(login, password, None, None)
            self.accounts.put(account)
        RegistrationThread.is_alive = False

    def email_boxes_open(self):
        dir_ = (os.path.dirname(self.email_boxes_path)
                if self.email_boxes_path is not None else '.')
        email_boxes_path = askopenfilename(
                    title='Email адреса',
                    initialdir=dir_,
                    filetypes=[('Text file', '*.txt')],
                    defaultextension='.txt', parent=self.parent)

        self.email_boxes_path = self.load_file(email_boxes_path, self.email_boxes_data, r"[\d\w]+@[\d\w]+\.\w+:.+\n?$")

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
        except (EnvironmentError, TypeError, json.JSONDecodeError):
            return

        self.status_bar.set("Файл загружен: %s" % os.path.basename(manifest_path))

    def proxy_open(self, window):
        dir_ = (os.path.dirname(self.proxy_path)
                if self.proxy_path is not None else '.')
        proxy_path = askopenfilename(
            title='Proxy',
            initialdir=dir_,
            filetypes=[('Text file (.txt)', '*.txt')],
            defaultextension='.txt', parent=window)

        self.proxy_path = self.load_file(proxy_path, self.proxy_data)
        window.destroy()

    def proxy_list_open(self, window):
        dir_ = (os.path.dirname(self.proxy_path)
                if self.proxy_path is not None else '.')
        proxy_urls_path = askopenfilename(
            title='Proxy URLS',
            initialdir=dir_,
            filetypes=[('Text file (.txt)', '*.txt')],
            defaultextension='.txt', parent=window)

        self.proxy_urls_path = self.load_file(proxy_urls_path, self.proxy_urls)
        window.destroy()

    def load_file(self, path, data, regexr=None):
        if not path:
            return ''
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for row, item in enumerate(f.readlines()):
                    if regexr and not re.match(regexr, item):
                        self.add_log("Недопустимое значение: {0} в строке {1}".format(item.strip(), row))
                        continue
                    data.append(item.strip())
        except (EnvironmentError, TypeError):
            showwarning("Ошибка", "Не удается открыть указанный файл", parent=self.parent)
            return ''

        if data:
            self.status_bar.set("Файл загружен: %s" % os.path.basename(path))
            return path

    def app_quit(self, *ignore):
        with open('database/userdata.txt', 'w') as f:
            json.dump(self.userdata, f)

        self.parent.destroy()


class RegistrationThread(threading.Thread):

    left = 0
    counter = 0
    error = False
    lock = threading.Lock()
    email_lock = threading.Lock()
    is_alive = True

    def __init__(self, window):
        super().__init__()
        self.daemon = True

        self.window = window
        self.proxy = None

    def run(self):
        self.set_proxy()
        while RegistrationThread.left > 0:
            with RegistrationThread.lock:
                RegistrationThread.left -= 1
            try:
                self.registrate_account()
            except (ProxyError, ConnectionError, Timeout):
                self.window.add_log("Нестабильное соединение: %s" % (self.proxy if self.proxy else "local ip"))
                self.set_proxy()
                with RegistrationThread.lock:
                    RegistrationThread.left += 1
            except Exception as err:
                with RegistrationThread.lock:
                    if not RegistrationThread.error:
                        showwarning("Ошибка %s" % err.__class__.__name__, err)
                        logger.critical(traceback.format_exc())
                        RegistrationThread.error = True
                return

    def registrate_account(self):
        self.window.status_bar.set('Создаю аккаунты, решаю капчи...')
        # try:
        #     login, passwd, email, email_password = steamreg.create_account_web(self.window.rucaptcha_api_key.get().strip(),
        #                                                                        RegistrationThread.email_lock, self.proxy)
        # except LimitReached as err:
        #     logging.error(err)
        #     if self.proxy:
        #         self.window.add_log("Достигнут лимит регистрации аккаунтов: %s. Меняю прокси..." % self.proxy)
        #     else:
        #         self.window.add_log("Достигнут лимит регистрации аккаунов для local ip.")
        #     return
        #
        # logger.info('Аккаунт: %s:%s', login, passwd)
        # self.window.add_log('Аккаунт зарегистрирован (%s, %s, %s)' % (self.proxy, login, passwd))
        #
        # with RegistrationThread.lock:
        #     self.save_unattached_account(login, passwd, email, email_password)
        # try:
        #     steam_client = steamreg.login(login, passwd, self.window.rucaptcha_api_key.get(), self.proxy,
        #                                   pass_login_captcha=self.window.pass_login_captcha.get())
        # except AuthException as err:
        #     logger.error(err)
        #     self.window.add_log("%s: не удается авторизоваться с этого айпи"
        #                         % (str(self.proxy).strip("<>") if self.proxy else "local ip"))
        #     self.set_proxy()
        #     return
        # except SteamAuthError as err:
        #     logger.error(err)
        #     self.window.add_log(err)
        #     return
        # except CaptchaRequired as err:
        #     logger.error(err)
        #     self.window.add_log("%s: требуется решить капчу для авторизации в аккаунты"
        #                         % (str(self.proxy).strip("<>") if self.proxy else "local ip"))
        #     self.set_proxy()
        #     return
        # steamreg.activate_account(steam_client)
        # steamreg.edit_profile(steam_client)
        # self.window.add_log("Профиль активирован: %s:%s" % (login, passwd))
        # account = Account(login, passwd, email, email_password)
        # self.window.accounts.put(account)
        RegistrationThread.counter += 1
        self.window.accounts_registrated.set("Аккаунтов зарегистрировано: %d" % RegistrationThread.counter)

    def set_proxy(self):
        if self.proxy is not None:
            self.proxy.close()
        proxy = self.window.reg_proxies.get()
        if proxy:
            self.window.add_log("Regger: " + str(proxy).strip("<>"))
        else:
            self.window.add_log("Regger: Использую local ip")
        self.proxy = proxy

    @staticmethod
    def save_unattached_account(login, passwd, email, email_password):
        with open('accounts.txt', 'a+') as f:
            f.write('%s:%s\n' % (login, passwd))

        with open(r'новые_аккаунты/%s.txt' % login, 'w') as f:
            f.write('%s:%s\nDropmail: %s\nDropmail mailbox recovery code: %s'
                    % (login, passwd, email, email_password))


class Binder(threading.Thread):

    lock = threading.Lock()
    counter = 0
    error = False

    def __init__(self, window, sms_service, amount):
        super().__init__()
        self.window = window
        self.amount = amount
        self.sms_service = sms_service
        self.number = None
        self.proxy = None
        self.used_codes = []

    def run(self):
        self.set_proxy()
        while True:
            pack = []
            with Binder.lock:
                self.fill_pack(pack)
            if not pack:
                return
            try:
                with Binder.lock:
                    self.get_new_number()
                for account in pack:
                    while True:
                        try:
                            self.bind_account(account)
                            break
                        except (ProxyError, ConnectionError, Timeout):
                            self.window.add_log("Нестабильное соединение: %s"
                                                % (self.proxy if self.proxy else "local ip"))
                            self.set_proxy()
            except Exception as err:
                with Binder.lock:
                    if not Binder.error:
                        showwarning("Ошибка %s" % err.__class__.__name__, err)
                        logger.critical(traceback.format_exc())
                        Binder.error = True
                return
            self.sms_service.set_operation_ok(self.number['tzid'])

    def fill_pack(self, pack):
        for _ in range(self.amount):
            while True:
                try:
                    account = self.window.accounts.get(timeout=30)
                    pack.append(account)
                    break
                except Empty:
                    if not RegistrationThread.is_alive:
                        return

    def bind_account(self, account):
        self.window.status_bar.set('Делаю привязку Mobile Guard...')
        login, passwd = account.login, account.password
        logger.info('Аккаунт: %s:%s', login, passwd)
        insert_log = self.log_wrapper(login)
        insert_log('Номер: ' + self.number['number'])
        insert_log('Логинюсь в аккаунт')
        try:
            steam_client = steamreg.mobile_login(login, passwd, self.window.rucaptcha_api_key.get(), self.proxy,
                                                 pass_login_captcha=self.window.pass_login_captcha.get())
        except AuthException as err:
            logger.error(err)
            self.window.add_log("%s: не удается авторизоваться с этого айпи"
                                % (str(self.proxy).strip("<>") if self.proxy else "local ip"))
            self.set_proxy()
            return
        except SteamAuthError as err:
            insert_log(err)
            return
        except CaptchaRequired as err:
            logger.error(err)
            insert_log("%s: требуется решить капчу для авторизации в аккаунты"
                       % (str(self.proxy).strip("<>") if self.proxy else "local ip"))
            self.set_proxy()
            return

        if steamreg.is_phone_attached(steam_client):
            insert_log('К аккаунту уже привязан номер')
            return

        try:
            sms_code, mobguard_data = self.add_authenticator(insert_log, steam_client)
        except SteamAuthError as err:
            error = 'Не удается привязать номер к аккаунту: %s. Ошибка: %s' % (login, err)
            logger.error(error)
            insert_log(error)
            return
        steamreg.finalize_authenticator_request(steam_client, mobguard_data, sms_code)
        mobguard_data['account_password'] = passwd
        offer_link = steamreg.fetch_tradeoffer_link(steam_client)
        self.save_attached_account(mobguard_data, account, self.number['number'], offer_link)
        if not self.window.autoreg.get():
            steamreg.activate_account(steam_client)
            steamreg.edit_profile(steam_client)
        insert_log('Guard успешно привязан')
        Binder.counter += 1
        self.window.accounts_binder.set("Аккаунтов привязано: %d" % Binder.counter)

    def add_authenticator(self, insert_log, steam_client):
        while True:
            insert_log('Делаю запрос Steam на добавление номера...')
            response = steamreg.addphone_request(steam_client, self.number['number'])
            if not response['success']:
                if "we couldn't send an SMS to your phone" in response.get('error_text', ''):
                    insert_log('Стим сообщил о том что, ему не удалось отправить SMS')
                    insert_log('Меняю номер...')
                    self.get_new_number(self.number['tzid'])
                    insert_log('Новый номер: ' + self.number['number'])
                    time.sleep(5)
                    continue
                raise SteamAuthError(response.get('error_text', None))

            insert_log('Жду SMS код...')
            attempts = 0
            success = False
            try:
                while attempts < 15:
                    if self.number['is_repeated']:
                        self.sms_service.request_repeated_number_usage(self.number['tzid'])
                    attempts += 1
                    sms_code = self.sms_service.get_sms_code(self.number['tzid'])
                    if sms_code and sms_code not in self.used_codes:
                        self.used_codes.append(sms_code)
                        success = True
                        break
                    time.sleep(4)
            except OnlineSimError as err:
                insert_log("Ошибка onlinesim: %s" % err)
                self.get_new_number(self.number['tzid'])
                insert_log('Новый номер: ' + self.number['number'])
                continue

            if not success:
                insert_log('Не доходит SMS. Пробую снова...')
                continue

            self.number['is_repeated'] = True

            insert_log('Делаю запрос на привязку гуарда...')
            mobguard_data = steamreg.add_authenticator_request(steam_client)
            response = steamreg.checksms_request(steam_client, sms_code)
            if 'The SMS code is incorrect' in response.get('error_text', ''):
                insert_log('Неверный SMS код %s. Пробую снова...' % sms_code)
                continue
            return sms_code, mobguard_data

    def get_new_number(self, tzid=0):
        if tzid:
            self.sms_service.set_operation_ok(tzid)
            self.used_codes.clear()
        is_repeated = False
        tzid = self.sms_service.request_new_number(country=self.window.country_code.get())
        number = self.sms_service.get_number(tzid)
        self.number = {'tzid': tzid, 'number': number, 'is_repeated': is_repeated}

    def save_attached_account(self, mobguard_data, account, number, offer_link):
        if self.window.autoreg.get():
            accounts_dir = 'новые_аккаунты'
            if self.window.fold_accounts.get():
                accounts_dir = os.path.join(accounts_dir, account.login)
                os.makedirs(accounts_dir)
        else:
            accounts_dir = 'загруженные_аккаунты'

        steamid = mobguard_data['Session']['SteamID']
        txt_path = os.path.join(accounts_dir, account.login + '.txt')
        mafile_path = os.path.join(accounts_dir, account.login + '.maFile')
        binding_date = datetime.date.today()
        revocation_code = mobguard_data['revocation_code']
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write('{account.login}:{account.password}\nДата привязки Guard: {binding_date}\nНомер: {number}\n'
                    'SteamID: {steamid}\nRCODE: {revocation_code}\nТрейд ссылка: {offer_link}\n'
                    'Dropmail: {account.email}\nDropmail mailbox recovery password: {account.email_password}'.format(**locals()))

        with open('accounts_guard.txt', 'a+') as f:
            f.write('%s:%s\n' % (account.login, account.password))

        if self.window.import_mafile.get():
            sda_path = os.path.join(os.path.dirname(self.window.manifest_path), account.login + '.maFile')
            data = {
                "encryption_iv": None,
                "encryption_salt": None,
                "filename": account.login + '.maFile',
                "steamid": int(steamid)
            }
            self.window.manifest_data["entries"].append(data)
            with open(self.window.manifest_path, 'w') as f1, open(sda_path, 'w') as f2:
                json.dump(self.window.manifest_data, f1)
                json.dump(mobguard_data, f2, separators=(',', ':'))

        with open(mafile_path, 'w') as f:
            json.dump(mobguard_data, f, separators=(',', ':'))

    def set_proxy(self):
        if self.proxy is not None:
            self.proxy.close()

        proxy = self.window.bind_proxies.get()

        if proxy:
            self.window.add_log("Binder: " + str(proxy).strip("<>"))
        else:
            self.window.add_log("Binder: Использую local ip")
        self.proxy = proxy

    def log_wrapper(self, login):
        def insert_log(text):
            self.window.add_log('%s (%s)' % (text, login))
        return insert_log


def launch():
    root = Tk()
    window = MainWindow(root)
    root.iconbitmap('database/app.ico')
    root.title('Steam Auto Authenticator v0.92')
    root.protocol("WM_DELETE_WINDOW", window.app_quit)
    root.mainloop()


if __name__ == '__main__':
    logging.getLogger("requests").setLevel(logging.ERROR)
    logger = logging.getLogger(__name__)
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    handler = logging.FileHandler('database/logs.txt', 'w', encoding='utf-8')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

launch()
