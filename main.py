import asyncio
import datetime
import imaplib
import os
import random
import threading
import traceback
from collections import namedtuple
from queue import Queue, Empty
from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import showwarning, askyesno, showinfo

import cert_human
import pyqiwi
from requests.exceptions import Timeout, ConnectionError, ProxyError
from proxybroker import Broker

from enums import *
from sms_services import *
from steamreg import SteamRegger, SteamAuthError, LimitReachedError
from steampy.login import AuthException, CaptchaRequired, LoginExecutor

logger = logging.getLogger('__main__')
logger.setLevel(logging.DEBUG)

logging.getLogger("requests").setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
handler = logging.FileHandler('database/logs.txt', 'w', encoding='utf-8')
handler.setFormatter(formatter)
logger.addHandler(handler)

logger.setLevel(logging.INFO)
cert_human.enable_urllib3_patch()

for dir_name in ('новые_аккаунты', 'загруженные_аккаунты'):
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

if not os.path.exists('database/userdata.txt'):
    with open('database/userdata.txt', 'w') as f:
        f.write('{}')

if not os.path.exists('accounts.txt'):
    with open('accounts.txt', 'w') as f:
        pass

if not os.path.exists("database/imap-hosts.json"):
    with open("database/imap-hosts.json", "w") as f:
        f.write("{}")

with open("database/interface_states.json", "r") as f:
    STATES = json.load(f)

loop = asyncio.get_event_loop()


class MainWindow:

    def __init__(self, parent):
        self.frame = Frame(parent)
        self.parent = parent
        self.is_running = False
        with open('database/userdata.txt', 'r') as file:
            self.userdata = json.load(file)
        with open('accounts.txt', 'r') as file:
            self.accounts_unbinded = [row.strip() for row in file.readlines()]

        self.accounts_binded = []

        self.accounts_binded = []

        self.queue = asyncio.Queue(loop=loop)
        self.accounts = Queue()
        self.reg_proxies = Queue()
        self.bind_proxies = Queue()

        self.number_countries = {}

        self.start_time = time.time()

        self.proxy_broker = None

        self.manifest_path = ''
        self.accounts_path = ''
        self.email_boxes_path = ''
        self.proxy_path = ''
        self.proxy_urls_path = ''
        self.real_names_path = ''
        self.countries_path = ''
        self.avatars_path = ''
        self.statuses_path = ''

        self.real_names = []
        self.countries = []
        self.avatars = []
        self.statuses = []
        self.proxy_data = []
        self.proxy_urls = []
        self.privacy_settings = {}
        self.email_boxes_data = []
        self.old_accounts = []
        self.imap_hosts = {}
        self.manifest_data = None

        self.autoreg = IntVar()
        self.import_mafile = IntVar()
        self.mobile_bind = IntVar()
        self.fold_accounts = IntVar()
        self.add_money_to_account = IntVar()
        self.remove_emails_from_file = IntVar()
        self.activate_profile = IntVar()
        self.selection_type = IntVar()
        self.selection_type.set(int(SelectionType.RANDOM))
        self.sms_service_type = IntVar()
        self.sms_service_type.set(int(SmsService.OnlineSim))
        self.captcha_service_type = IntVar()
        self.captcha_service_type.set(int(CaptchaService.RuCaptcha))

        self.onlinesim_api_key = StringVar()
        self.captcha_api_key = StringVar()
        self.qiwi_api_key = StringVar()
        self.free_games = StringVar()
        self.paid_games = StringVar()
        self.new_accounts_amount = IntVar()
        self.accounts_per_number = IntVar()
        self.amount_of_binders = IntVar()
        self.amount_of_binders.set(1)
        self.private_email_boxes = IntVar()
        self.accounts_per_proxy = IntVar()
        self.accounts_per_proxy.set(10)
        self.status_bar = StringVar()
        self.country_code = StringVar()
        self.country_code.set('Россия')
        self.proxy_type = IntVar()
        self.pass_login_captcha = IntVar()
        self.money_to_add = IntVar()
        self.captcha_host = StringVar()
        self.onlinesim_host = StringVar()
        self.imap_host = StringVar()
        self.email_domains = StringVar()

        self.accounts_registrated_stat = StringVar()
        self.accounts_registrated_stat.set("Аккаунтов зарегистрировано:")
        self.accounts_binded_stat = StringVar()
        self.accounts_binded_stat.set("Аккаунтов привязано:")
        self.captcha_balance_stat = StringVar()
        self.captcha_balance_stat.set("Баланс CAPTCHA сервиса:")
        self.captchas_resolved_stat = StringVar()
        self.captchas_resolved_stat.set("Капч решено успешно:")
        self.captchas_failed_stat = StringVar()
        self.captchas_failed_stat.set("Капч не удалось решить:")
        self.captchas_expenses_stat = StringVar()
        self.captchas_expenses_stat.set("Потрачено на капчи:")
        self.numbers_used_stat = StringVar()
        self.numbers_used_stat.set("Использовано номеров:")
        self.onlinesim_balance_stat = StringVar()
        self.onlinesim_balance_stat.set("Баланс SIM сервиса:")
        self.numbers_failed_stat = StringVar()
        self.numbers_failed_stat.set("Недействительных номеров:")
        self.numbers_expenses_stat = StringVar()
        self.numbers_expenses_stat.set("Потрачено на SIM номера:")
        self.accounts_unregistrated_stat = StringVar()
        self.accounts_unregistrated_stat.set("Осталось аккаунтов зарегистрировать:")
        self.accounts_unbinded_stat = StringVar()
        self.accounts_unbinded_stat.set("Осталось аккаунтов привязать:")
        self.proxies_loaded_stat = StringVar()
        self.proxies_loaded_stat.set("Прокси в очереди:")
        self.proxies_limited_stat = StringVar()
        self.proxies_limited_stat.set("Прокси залимичено Steam:")
        self.proxies_bad_stat = StringVar()
        self.proxies_bad_stat.set("Недействительных прокси:")
        self.time_stat = StringVar()
        self.time_stat.set("Времени прошло: 0")

        self.login_template = StringVar()
        self.nickname_template = StringVar()
        self.passwd_template = StringVar()

        self.menubar = Menu(parent)
        self.load_menu = Menu(self.menubar, tearoff=0)
        parent['menu'] = self.menubar

        self.accounts_per_number_label = Label(self.frame, text='Количество аккаунтов на 1 номер:')
        self.accounts_per_number_entry = Entry(self.frame, textvariable=self.accounts_per_number,
                                               width=2, disabledforeground='#808080')

        self.onlinesim_settings_bttn = Button(self.frame, text='Настроить сервис онлайн номеров',
                                              command=self.deploy_onlinenum_window, bg='#CEC8C8', relief=GROOVE)

        self.new_accounts_amount_label = Label(self.frame, text='Количество аккаунтов для регистрации:')
        self.new_accounts_amount_entry = Entry(self.frame, textvariable=self.new_accounts_amount, width=4,
                                               disabledforeground='#808080')

        self.captcha_settings_bttn = Button(self.frame, text='Настроить капча сервис',
                                            command=self.deploy_captcha_window, bg='#CEC8C8', relief=GROOVE)

        tools_frame = Frame(self.parent)
        self.tools_label = Label(tools_frame, text='Инструменты:')
        self.options_label = Label(tools_frame, text='Опции:')
        self.autoreg_checkbutton = Checkbutton(tools_frame, text='Создавать новые аккаунты',
                                               variable=self.autoreg, command=self.set_states,
                                               disabledforeground='#808080')
        self.add_money_to_account_checkbutton = Checkbutton(tools_frame, text='Пополнять баланс на аккаунтах',
                                                            variable=self.add_money_to_account)

        self.mafile_checkbutton = Checkbutton(tools_frame, text='Импортировать maFile в SDA',
                                              variable=self.import_mafile, command=self.set_states,
                                              disabledforeground='#808080')
        self.mobile_bind_checkbutton = Checkbutton(tools_frame, text='Привязывать Mobile Guard',
                                                   variable=self.mobile_bind, command=self.set_states,
                                                   disabledforeground='#808080')
        self.fold_accounts_checkbutton = Checkbutton(tools_frame, text='Раскладывать по папкам',
                                                     variable=self.fold_accounts, disabledforeground='#808080')
        self.amount_of_binders_label = Label(tools_frame, text='Количество потоков для привязки:')
        self.amount_of_binders_field = Entry(tools_frame, textvariable=self.amount_of_binders,
                                             disabledforeground='#808080', width=2)

        self.start_button = Button(tools_frame, text='Начать', command=self.start_process,
                                   bg='#CEC8C8', relief=GROOVE, width=25)

        self.stop_button = Button(tools_frame, text='Остановить', command=self.stop_process,
                                  bg='#CEC8C8', relief=GROOVE, width=25)

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
        self.caption_label = Label(log_frame, text='Shamanovski software')

        if self.userdata:
            self.set_attributes()
        self.load_files()
        self.set_countries()

        self.pack_widgets()

    def set_states(self):
        for checkbutton_name, configs in sorted(STATES.items(), key=lambda item: item[1]["priority"]):
            try:
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
            except AttributeError:
                continue

    @staticmethod
    def adjust_state(flag, state):
        reversed_states = {NORMAL: DISABLED, DISABLED: NORMAL}
        if not flag:
            state = reversed_states[state]
        return state

    def set_attributes(self):
        for attr_name, value in self.userdata.items():
            try:
                attribute = self.__getattribute__(attr_name)
            except AttributeError:
                continue
            try:
                attribute.set(value)
            except AttributeError:
                self.__setattr__(attr_name, value)

    def load_files(self):
        self.load_manifest(self.manifest_path)
        self.load_file(self.email_boxes_path, self.email_boxes_data)
        # self.load_file(self.accounts_path, self.old_accounts)
        self.load_file(self.proxy_path, self.proxy_data)
        self.load_file(self.proxy_urls_path, self.proxy_urls)
        self.load_file(self.avatars_path, self.avatars)
        self.load_file(self.statuses_path, self.statuses)
        self.load_file(self.countries_path, self.countries)
        self.load_file(self.real_names_path, self.real_names)

    def pack_widgets(self):
        self.menubar.add_cascade(label="Загрузить...", menu=self.load_menu)
        self.load_menu.add_command(label="Свои аккаунты", command=self.accounts_open)
        self.load_menu.add_command(label="Свои почты", command=self.email_boxes_open)
        self.load_menu.add_command(label="SDA Manifest", command=self.manifest_open)

        self.menubar.add_cascade(label="Настроить прокси", command=self.deploy_proxy_widget)
        self.menubar.add_cascade(label="Открыть статистику", command=self.deploy_stats_window)
        self.menubar.add_cascade(label="Задать шаблон", command=self.deploy_template_window)
        self.menubar.add_cascade(label="Дополнительно", command=self.deploy_additional_settings_window)

        self.onlinesim_settings_bttn.grid(row=0, column=0, padx=3, pady=5, sticky=W)
        self.captcha_settings_bttn.grid(row=1, column=0, padx=3, pady=5, sticky=W)

        self.new_accounts_amount_label.grid(row=2, column=0, pady=5, sticky=W)
        self.new_accounts_amount_entry.grid(row=2, column=1, pady=5, padx=5, sticky=W)

        self.accounts_per_number_label.grid(row=3, column=0, pady=5, sticky=W)
        self.accounts_per_number_entry.grid(row=3, column=1, pady=5, padx=5, sticky=W)

        self.tools_label.grid(row=0, column=0, pady=3, sticky=W)
        self.autoreg_checkbutton.grid(row=1, column=0, sticky=W)
        self.mobile_bind_checkbutton.grid(row=1, column=1, pady=1, sticky=W)
        self.options_label.grid(row=2, column=0, pady=3, sticky=W)

        self.mafile_checkbutton.grid(row=3, column=1, pady=1)
        self.fold_accounts_checkbutton.grid(row=4, column=1, pady=1, sticky=W)
        self.add_money_to_account_checkbutton.grid(row=4, column=0, pady=1, sticky=W)
        self.amount_of_binders_label.grid(row=5, column=0, pady=1, sticky=W)
        self.amount_of_binders_field.grid(row=5, column=1, columnspan=2, pady=1, sticky=W)

        self.start_button.grid(row=6, pady=10, column=0)
        self.stop_button.grid(row=6, pady=10, column=1)
        self.log_label.grid(row=0, column=0, pady=5, sticky=W)
        self.log_box.grid(row=1, column=0, sticky=NSEW)
        self.scrollbar.grid(row=1, column=1, sticky=NS)
        self.scrollbar_x.grid(row=2, column=0, sticky=EW)
        self.status_bar_label.grid(row=3, column=0, columnspan=2, sticky=W, pady=5)
        self.caption_label.grid(row=3, column=0, sticky=E)

    def deploy_stats_window(self):
        top = Toplevel(master=self.frame)
        top.title("Статистика")
        top.iconbitmap('database/stats.ico')

        lbl14 = Label(top, text="Аккаунты")
        lbl14.grid(row=3, column=0, padx=5, pady=5, sticky=W)

        lbl = Label(top, textvariable=self.accounts_registrated_stat)
        lbl.grid(row=4, column=0, padx=5, pady=5, sticky=W)

        lbl2 = Label(top, textvariable=self.accounts_binded_stat)
        lbl2.grid(row=4, column=1, padx=5, pady=5, sticky=W)

        lbl3 = Label(top, textvariable=self.accounts_unregistrated_stat)
        lbl3.grid(row=5, column=0, padx=5, pady=10, sticky=W)

        lbl4 = Label(top, textvariable=self.accounts_unbinded_stat)
        lbl4.grid(row=5, column=1, padx=5, pady=10, sticky=W)

        lbl13 = Label(top, text="Капчи")
        lbl13.grid(row=6, column=0, padx=5, pady=5, sticky=W)

        lbl16 = Label(top, textvariable=self.captcha_balance_stat)
        lbl16.grid(row=7, column=0, padx=5, pady=5, sticky=W)

        lbl5 = Label(top, textvariable=self.captchas_resolved_stat)
        lbl5.grid(row=7, column=1, padx=5, pady=5, sticky=W)

        lbl6 = Label(top, textvariable=self.captchas_failed_stat)
        lbl6.grid(row=8, column=0, padx=5, pady=5, sticky=W)

        lbl7 = Label(top, textvariable=self.captchas_expenses_stat)
        lbl7.grid(row=8, column=1, padx=5, pady=10, sticky=W)

        lbl15 = Label(top, text="Номера")
        lbl15.grid(row=9, column=0, padx=5, pady=5, sticky=W)

        Label(top, textvariable=self.onlinesim_balance_stat).grid(row=10, column=0, padx=5, pady=5, sticky=W)

        lbl8 = Label(top, textvariable=self.numbers_expenses_stat)
        lbl8.grid(row=10, column=1, padx=5, pady=5, sticky=W)

        lbl8 = Label(top, textvariable=self.numbers_used_stat)
        lbl8.grid(row=11, column=0, padx=5, pady=5, sticky=W)

        lbl8 = Label(top, textvariable=self.numbers_failed_stat)
        lbl8.grid(row=11, column=1, padx=5, pady=10, sticky=W)

        lbl16 = Label(top, text="Прокси")
        lbl16.grid(row=12, column=0, padx=5, pady=5, sticky=W)

        lbl9 = Label(top, textvariable=self.proxies_loaded_stat)
        lbl9.grid(row=15, column=0, padx=5, pady=5, sticky=W)

        lbl10 = Label(top, textvariable=self.proxies_limited_stat)
        lbl10.grid(row=15, column=1, padx=5, pady=5, sticky=W)

        lbl11 = Label(top, textvariable=self.proxies_bad_stat)
        lbl11.grid(row=16, column=1, padx=5, pady=10, sticky=W)

        lbl12 = Label(top, textvariable=self.time_stat)
        lbl12.grid(row=17, column=0, padx=5, pady=15, sticky=W)

    def deploy_additional_settings_window(self):
        def add_imap_host():
            if not self.imap_host.get() or not self.email_domains.get():
                showinfo("Сообщение", "Задайте IMAP сервер и почтовые домены соответствующие ему", parent=top)
                return
            LoginExecutor.IMAP_HOSTS[self.imap_host.get()] = self.email_domains.get().split(",")
            showinfo("Сообщение", "IMAP сервер и почтовые домены связанные с ним успешно добавлены", parent=top)

        def list_imap_hosts(master):
            imap_hosts_wiget = Toplevel(master=master)
            imap_hosts_wiget.title("IMAP сервера")
            row = 0
            for imap_server, email_domains in self.imap_hosts.items():
                Label(imap_hosts_wiget, text="%s: %s" % (imap_server, ", ".join(email_domains)))\
                    .grid(column=0, row=row, pady=5)
                row += 1

        top = Toplevel(master=self.frame)
        top.iconbitmap('database/plus-blue.ico')
        top.title("Дополнительные фукнции")

        Label(top, text="Добавить бесплатные игры (subid через запятую):").grid(row=0, column=0, padx=5, pady=5, sticky=W)
        Entry(top, textvariable=self.free_games, width=30) \
            .grid(row=0, column=1, padx=5, pady=5, sticky=W)

        Label(top, text="Купить платные игры (subid через запятую):").grid(row=1, column=0, padx=5, pady=5, sticky=W)
        Entry(top, textvariable=self.paid_games, width=30) \
            .grid(row=1, column=1, padx=5, pady=5, sticky=W)

        Label(top, text="Пополнить баланс на аккаунтах").grid(row=2, column=0, padx=5, pady=5, sticky=W)
        Label(top, text="QIWI Api Key:").grid(row=3, column=0, padx=5, pady=5, sticky=W)
        Entry(top, textvariable=self.qiwi_api_key, width=30) \
            .grid(row=3, column=1, padx=5, pady=5, sticky=W)

        Label(top, text="Сумма (в рублях):").grid(row=4, column=0, padx=5, pady=5, sticky=W)
        Entry(top, textvariable=self.money_to_add, width=5) \
            .grid(row=4, column=1, padx=5, pady=5, sticky=W)

        Label(top, text="Почты").grid(row=5, column=0, padx=5, pady=5, sticky=W)
        Checkbutton(top, text="Удалять использованные почты с файла", variable=self.remove_emails_from_file) \
            .grid(row=7, column=0, padx=5, pady=5, sticky=W)

        Label(top, text="IMAP сервер:").grid(column=0, row=8, padx=5, pady=5, sticky=W)
        Entry(top, textvariable=self.imap_host, width=30) \
            .grid(row=8, column=1, padx=5, pady=5, sticky=W)

        Label(top, text="Домены (через запятую без пробелов)").grid(column=0, row=9, padx=5, pady=5, sticky=W)
        Entry(top, textvariable=self.email_domains, width=30) \
            .grid(row=9, column=1, padx=5, pady=5, sticky=W)

        Button(top, text="Добавить", command=add_imap_host) \
            .grid(row=10, column=0, padx=5, pady=5, sticky=W)

        Button(top, text="Просмотреть список IMAP серверов", command=lambda: list_imap_hosts(top)) \
            .grid(row=10, column=0, columnspan=2, padx=5, pady=5, sticky=E)

        Label(top, text="Аккаунты").grid(row=11, column=0, padx=5, pady=5, sticky=W)
        Checkbutton(top, text="Активировать профиль аккаунта", variable=self.activate_profile) \
            .grid(row=12, column=0, padx=5, pady=5, sticky=W)

        Label(top, text="Комментарии").grid(row=15, column=0, padx=5, pady=5, sticky=W)
        Label(top, text="subid игры можно узнать на steamdb.info (например https://steamdb.info/app/730/subs/)"
                        "\nлибо в исходном коде страницы игры в магазине Steam"
                        "\n\nГенерировать почты означает, что вы загружаете одну единственную почту\nна которую "
                        "перенаправляются все письма от сгенерированных",
              justify=LEFT).grid(column=0, columnspan=2, row=16, padx=5, sticky=W)

        Button(top, command=top.destroy, text="Подтвердить").grid(column=0, columnspan=2, row=17, padx=5, pady=5)

    def deploy_template_window(self):
        top = Toplevel(master=self.frame)
        top.title("Шаблоны")
        Label(top, text="Шаблон для логина:").grid(row=0, column=0, padx=5, pady=5, sticky=W)
        Entry(top, textvariable=self.login_template, width=20)\
            .grid(row=0, column=1, padx=5, pady=5, sticky=W)

        Label(top, text="Шаблон для пароля:").grid(row=1, column=0, padx=5, pady=5, sticky=W)
        Entry(top, textvariable=self.passwd_template, width=20)\
            .grid(row=1, column=1, padx=5, pady=5, sticky=W)

        Label(top, text="Шаблон для никнейма профиля:").grid(row=2, column=0, padx=5, pady=5, sticky=W)
        Entry(top, textvariable=self.nickname_template, width=20)\
            .grid(row=2, column=1, padx=5, pady=5, sticky=W)

        Label(top, text="Если вы хотите, чтобы никнейм генерировался рандомно, то оставьте поле пустым.\n"
                        "Если вы хотите, чтобы никнейм был таким же, как логин, напишите в поле {login}", justify=LEFT)\
            .grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky=W)

        Label(top, text="Выборка элементов списка:").grid(row=4, column=0, padx=5, pady=5, sticky=W)
        rbttn = Radiobutton(top, text="Рандомная", variable=self.selection_type, value=int(SelectionType.RANDOM))
        rbttn.grid(column=0, row=5, padx=5, pady=5, sticky=W)
        rbttn2 = Radiobutton(top, text="Последовательная", variable=self.selection_type, value=int(SelectionType.CONSISTENT))
        rbttn2.grid(column=1, row=5, padx=5, pady=5, sticky=W)

        Label(top, text="Реальные имена:").grid(row=6, column=0, padx=5, pady=5, sticky=W)
        Button(top, text="Загрузить", relief=GROOVE, command=lambda: self.file_open(top, "real_names_path", "Real names", self.real_names, r".+\n"))\
            .grid(row=6, column=1, padx=5, pady=5, sticky=W)

        Label(top, text="Страны:").grid(row=7, column=0, padx=5, pady=5, sticky=W)
        Button(top, text="Загрузить", relief=GROOVE, command=lambda: self.file_open(top, "countries_path", "Countries", self.countries, r"\w\w\n"))\
            .grid(row=7, column=1, padx=5, pady=5, sticky=W)

        Label(top, text="Аватары:").grid(row=8, column=0, padx=5, pady=5, sticky=W)
        Button(top, text="Загрузить", relief=GROOVE, command=lambda: self.file_open(top, "avatars_path", "Avatars", self.avatars, r"https?://.+\n"))\
            .grid(row=8, column=1, padx=5, pady=5, sticky=W)

        Label(top, text="Статусы:").grid(row=9, column=0, padx=5, pady=5, sticky=W)
        Button(top, text="Загрузить", relief=GROOVE, command=lambda: self.file_open(top, "statuses_path", "Statuses", self.statuses, r".+\n"))\
            .grid(row=9, column=1, padx=5, pady=5, sticky=W)

        Label(top, text="Примеры шаблона логина (пароля и никнейма):\nmy{num}login либо qwerty{num},\n"
                        "где num автоматически преобразуется программой в порядковое число\n\n"
                        "Страны указываются в формате ISO 3166-1 Alpha 2 (например: RU, US)\n\n"
                        "Аватары: URL ссылки на изображения")\
            .grid(row=10, columnspan=2, padx=5, pady=5, sticky=W)

        Button(top, command=top.destroy, text="Подтвердить").grid(column=0, columnspan=2, row=11, padx=5, pady=5)

    def add_log(self, message):
        self.log_box.insert(END, message)
        if not self.log_frozen:
            self.log_box.yview(END)

    def freeze_log(self, *ignore):
        self.log_frozen = True

    def unfreeze_log(self, *ignore):
        self.log_frozen = False

    def run_process(self):
        new_accounts_amount = self.new_accounts_amount.get()
        onlinesim_api_key = self.onlinesim_api_key.get()
        sim_host = self.onlinesim_host.get()
        threads = []
        sms_service = None
        if self.mobile_bind.get():
            if self.old_accounts:
                self.put_from_text_file()
            if self.sms_service_type.get() == SmsService.OnlineSim:
                sms_service = OnlineSimApi(onlinesim_api_key, sim_host)
            elif self.sms_service_type.get() == SmsService.SmsActivate:
                sms_service = SmsActivateApi(onlinesim_api_key, sim_host)
            for _ in range(self.amount_of_binders.get()):
                t = Binder(self, sms_service, self.accounts_per_number.get())
                threads.append(t)
            Binder.total_amount = len(self.old_accounts)

        if self.autoreg.get():
            self.init_threads(threads, new_accounts_amount)
            Binder.total_amount = self.new_accounts_amount.get()
        for thread in threads:
            thread.start()
        RegistrationThread.is_alive = False
        for thread in threads:
            thread.join()

        self.status_bar.set("Готово")
        self.is_running = False

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
            if not self.accounts_path and not self.email_boxes_path:
                showwarning("Ошибка", "Не загружен текстовик с почтами", parent=self.parent)
                return False

            try:
                self.check_templates()
            except ValueError as err:
                showwarning("Ошибка в шаблоне", err, parent=self.parent)

            if not self.captcha_api_key.get():
                showwarning("Ошибка", 'Не указан api ключ Captcha сервиса')
                return False
            try:
                self.check_captcha_key()
            except Exception as err:
                showwarning("Ошибка Captcha", err, parent=self.parent)
                return False
            try:
                if self.new_accounts_amount.get() <= 0:
                    raise ValueError
            except (TclError, ValueError):
                showwarning("Ошибка", "Количество аккаунтов для "
                                      "регистрации должно составлять от 1 до 33",
                            parent=self.parent)
                return False

            if self.paid_games.get():
                is_agree = askyesno("Покупка игр", "Вы уверены что хотите покупать игры на аккаунтах?",
                                    icon='warning')
                if not is_agree:
                    return False

            if self.add_money_to_account.get():
                if not self.money_to_add.get():
                    showwarning("Ошибка", "Не указана сумма для пополнения баланса")
                    return False

                if not self.qiwi_api_key.get():
                    showwarning("Ошибка", "Не указан QIWI Api ключ")
                    return False

                is_agree = askyesno("Пополнение баланса", "Вы уверены что хотите пополнять баланс на аккаунтах?",
                                    icon='warning')
                if not is_agree:
                    return False

        if self.mobile_bind.get():
            try:
                if not 0 < self.accounts_per_number.get() <= 15:
                    raise ValueError
            except (TclError, ValueError):
                showwarning("Ошибка", "Введите корректное число аккаунтов, "
                                      "связанных с 1 номером (больше нуля но меньше 15-и).",
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

            if not self.old_accounts and not self.autoreg.get():
                showwarning("Ошибка", "Не указан путь к файлу с данными от аккаунтов. "
                                      "Если у вас нет своих аккаунтов, то поставьте галочку 'Создавать новые аккаунты'",
                            parent=self.parent)
                return False

        return True

    def save_input(self):
        exceptions = ('status_bar', 'license', 'stat', 'quota', 'accounts_path')
        for field, value in self.__dict__.items():
            if list(filter(lambda exception: exception in field, exceptions)) or "status" in field:
                continue
            if issubclass(value.__class__, Variable) or 'path' in field or 'imap_hosts' in field:
                try:
                    value = value.get()
                except (AttributeError, TypeError):
                    pass
                self.userdata[field] = value

    def init_threads(self, threads, threads_amount=20):
        if threads_amount > 20:
            threads_amount = 20
        for _ in range(threads_amount):
            t = RegistrationThread(self)
            threads.append(t)
        RegistrationThread.left = self.new_accounts_amount.get()

    async def produce_proxies(self):
        if not self.proxy_type.get():
            return
        pass_login_captcha = self.pass_login_captcha.get()
        ctr = 0
        while True:
            proxy = await self.queue.get()
            if proxy is None:
                return
            self.status_bar.set("Работаю...")
            try:
                ban = steamregger.check_proxy_ban(proxy)
            except (ProxyError, ConnectionError, Timeout):
                self.add_log("Нестабильное соединение: %s" % proxy)
                continue
            if ban and pass_login_captcha:
                self.add_log("%s: требуется решить капчу для авторизации в аккаунты" % str(proxy).strip("<>"))
                continue

            self.reg_proxies.put(proxy)
            self.bind_proxies.put(proxy)
            ctr += 1
            self.proxies_loaded_stat.set("Прокси в очереди: %d" % ctr)

    def deploy_proxy_widget(self):
        def set_state():
            # set states of buttons
            state = DISABLED
            proxy_type = self.proxy_type.get()

            if proxy_type in (int(Proxy.Url), int(Proxy.File)):
                state = DISABLED

            load_proxy_bttn.config(state=state)
            load_proxy_list_bttn.config(state=state)

        top = Toplevel(master=self.frame)
        top.title("Настройка прокси")
        top.iconbitmap('database/proxy.ico')

        checkbttn2 = Checkbutton(top, text="\nПропускать прокси с которыми требуется\nрешать капчи для авторизации",
                                 variable=self.pass_login_captcha)
        checkbttn2.grid(column=1, row=0, pady=5, sticky=W)

        Label(top, text='Количество аккаунтов на 1 прокси:').grid(row=1, column=0, pady=5, sticky=W)
        Entry(top, width=3, textvariable=self.accounts_per_proxy).grid(row=1, column=1, pady=5, padx=5, sticky=W)

        lbl = Label(top, text="Тип проксирования:")
        lbl.grid(column=0, row=2, padx=5, pady=10, sticky=W)

        rbttn2 = Radiobutton(top, command=set_state, text="Загрузить ссылки на страницы с прокси:",
                             variable=self.proxy_type, value=int(Proxy.Url))
        rbttn2.grid(column=0, row=4, padx=5, pady=5, sticky=W)

        load_proxy_list_bttn = Button(top, state=DISABLED, text="Загрузить", command=lambda: self.proxy_list_open(top),
                                      relief=GROOVE)
        load_proxy_list_bttn.grid(column=0, row=5, padx=10, pady=5, sticky=W)

        rbttn3 = Radiobutton(top, command=set_state, text="Загрузить свои прокси:", variable=self.proxy_type,
                             value=int(Proxy.File))
        rbttn3.grid(column=0, row=6, padx=5, pady=5, sticky=W)

        load_proxy_bttn = Button(top, state=DISABLED, text="Загрузить", command=lambda: self.proxy_open(top),
                                 relief=GROOVE)
        load_proxy_bttn.grid(column=0, row=7, padx=10, pady=5, sticky=W)

        rbttn4 = Radiobutton(top, command=set_state, text="Не использовать прокси", variable=self.proxy_type, value=0)
        rbttn4.grid(column=0, row=8, padx=5, pady=5, sticky=W)

        confirm_bttn = Button(top, command=top.destroy, text="Подтвердить")
        confirm_bttn.grid(column=0, columnspan=2, row=9, padx=5, pady=5)

        for rbttn in (rbttn2, rbttn3, rbttn4):
            if self.proxy_type.get() == rbttn.config("value"):
                rbttn.select()
                break

        set_state()
        top.focus_set()

    def deploy_onlinenum_window(self):
        def deploy_countries_list(event=True):
            self.number_countries.clear()
            self.set_countries()
            if event:
                self.country_code.set("Россия")

                if self.sms_service_type.get() == SmsService.OnlineSim:
                    self.onlinesim_host.set("onlinesim.ru")
                elif self.sms_service_type.get() == SmsService.SmsActivate:
                    self.onlinesim_host.set("sms-activate.ru")

            OptionMenu(top, self.country_code, *sorted(self.number_countries.keys())) \
                .grid(row=5, padx=5, pady=5, sticky=W)

        top = Toplevel(master=self.frame)
        top.title("Настройка сервиса онлайн номеров")
        top.iconbitmap('database/sim.ico')

        Label(top, text='Сервис:').grid(row=0, column=0, pady=5, padx=5, sticky=W)
        Radiobutton(top, text='OnlineSim', variable=self.sms_service_type, value=int(SmsService.OnlineSim),
                    command=deploy_countries_list).grid(row=1, column=0, pady=5, padx=5, sticky=W)
        Radiobutton(top, text='SMS Activate', variable=self.sms_service_type, value=int(SmsService.SmsActivate),
                    command=deploy_countries_list).grid(row=1, column=1, pady=5, padx=5, sticky=W)

        Label(top, text='api key:').grid(row=2, column=0, pady=5, padx=5, sticky=W)
        Entry(top, textvariable=self.onlinesim_api_key, width=33)\
            .grid(row=2, column=1, columnspan=2, pady=5, padx=5, sticky=W)

        Label(top, text='Host:').grid(row=3, column=0, pady=5, padx=5, sticky=W)
        Entry(top, textvariable=self.onlinesim_host, width=33, )\
            .grid(row=3, column=1, columnspan=2, pady=5, padx=5, sticky=W)

        Label(top, text='Страна номера:').grid(row=4, column=0, pady=3, sticky=W)
        deploy_countries_list(event=False)

        Button(top, command=top.destroy, text="Подтвердить").grid(column=0, columnspan=3, row=6, padx=5, pady=5)

    def set_countries(self):
        if self.sms_service_type.get() == SmsService.SmsActivate:
            countries_string = "0 - Россия, 1 - Украина, 2 - Казахстан, 3 - Китай, 4 - Филиппины, 5 - Мьянма, " \
                               "6 - Индонезия, 7 - Малайзия, 8 - Кения, 9 - Танзания, 10 - Вьетнам, 11 - Кыргызстан," \
                               " 12 - США, 13 - Израиль, 14 - Гонконг, 15 - Польша, 16 - Великобритания, " \
                               "17 - Мадагаскар, 18 - Конго, 19 - Нигерия, 20 - Макао, 21 - Египет, 23 - Ирландия, " \
                               "24 - Камбоджа"
            for item in countries_string.split(", "):
                value, delimiter, country = item.partition(" - ")
                self.number_countries[country] = value

        elif self.sms_service_type.get() == SmsService.OnlineSim:
            self.number_countries = {
                "Россия": "7",
                "Китай": "86",
                "Нигерия": "234",
                "Кот д'ивуар": "225",
                "Украина": "380",
                "Казахстан": "77",
                "Египет": "20"
            }

    def deploy_captcha_window(self):
        top = Toplevel(master=self.frame)
        top.title("Настройка капчи сервиса")
        top.iconbitmap('database/captcha.ico')

        Label(top, text='Сервис:').grid(row=0, column=0, pady=5, padx=5, sticky=W)
        Radiobutton(top, text='RuCaptcha', variable=self.captcha_service_type, value=int(CaptchaService.RuCaptcha))\
            .grid(row=1, column=0, pady=5, padx=5, sticky=W)
        Radiobutton(top, text='AntiCaptcha', variable=self.captcha_service_type, value=int(CaptchaService.AntiCaptcha))\
            .grid(row=1, column=1, pady=5, padx=5, sticky=W)

        Label(top, text='api key:').grid(row=2, column=0, pady=5, padx=5, sticky=W)
        Entry(top, textvariable=self.captcha_api_key, width=33) \
            .grid(row=2, column=1, columnspan=2, pady=5, padx=5, sticky=W)

        Label(top, text='Host:').grid(row=3, column=0, pady=5, padx=5, sticky=W)
        Entry(top, textvariable=self.captcha_host, width=33) \
            .grid(row=3, column=1, columnspan=2, pady=5, padx=5, sticky=W)

        Button(top, command=top.destroy, text="Подтвердить").grid(column=0, columnspan=3, row=4, padx=5, pady=5)

    def check_captcha_key(self):
        balance = steamregger.captcha_service.get_balance()
        self.captcha_balance_stat.set("Баланс CAPTCHA сервиса: %s" % balance)

    def start_process(self):
        if self.is_running:
            RegistrationThread.lock.release()
            Binder.lock.release()
            self.status_bar.set("В процессе...")
            return

        steamregger.set_captcha_service()
        if not self.check_input():
            return
        self.update_clock()

        t = threading.Thread(target=self.init_proxy_producing)
        t.daemon = True
        t.start()

        t = threading.Thread(target=self.run_process)
        t.daemon = True
        t.start()

        self.is_running = True

    def stop_process(self):
        RegistrationThread.lock.acquire(blocking=False)
        Binder.lock.acquire(blocking=False)
        self.status_bar.set("Останавливаю...")

    def init_proxy_producing(self):
        proxy_type = self.proxy_type.get()

        providers = None
        if proxy_type == Proxy.Url:
            providers = self.proxy_urls
        self.proxy_broker = Broker(queue=self.queue, loop=loop, providers=providers)

        protos = [('HTTP', ('Anonymous', 'High')), 'HTTPS', 'SOCKS4', 'SOCKS5']
        data = None
        if proxy_type == Proxy.File:
            with open(self.proxy_path) as file:
                data = file.read()
        asyncio.ensure_future(self.proxy_broker.find(
            data=data, types=protos), loop=loop)
        self.status_bar.set("Чекаю прокси...")
        loop.run_until_complete(self.produce_proxies())
        loop.close()
        self.add_log("Закончил чекинг прокси")
        self.add_log("Прокси загружены")

    def accounts_open(self):
        dirpath = (os.path.dirname(self.accounts_path)
                   if self.accounts_path is not None else '.')
        accounts_path = askopenfilename(
                    title='логин:пасс аккаунтов',
                    initialdir=dirpath,
                    filetypes=[('Text file', '*.txt')],
                    defaultextension='.txt', parent=self.parent)

        self.accounts_path = self.load_file(accounts_path, self.old_accounts, r"[\d\w@.]+:.+\n")

    def put_from_text_file(self):
        Account = namedtuple("Account", ['login', 'password', 'email', 'email_password'])
        for item in self.old_accounts:
            try:
                login, password, email, email_password = item.split(':')[:4]
            except ValueError:
                login, password = item.split(":")[:2]
                if not self.email_boxes_data:
                    showwarning("Ошибка", "Аккаунты должны быть представлены с почтой формата login:pass:emailpass")
                    raise
                try:
                    emailbox = self.email_boxes_data.pop()
                    email, email_password = emailbox.split(":")
                except IndexError:
                    self.add_log("Почты загружены")
                    return

            account = Account(login, password, email, email_password)
            self.accounts.put(account)
            if item not in self.accounts_unbinded:
                self.accounts_unbinded.append(item)
        RegistrationThread.is_alive = False

    def email_boxes_open(self):
        dir_ = (os.path.dirname(self.email_boxes_path)
                if self.email_boxes_path is not None else '.')
        email_boxes_path = askopenfilename(
                    title='Email адреса',
                    initialdir=dir_,
                    filetypes=[('Text file', '*.txt')],
                    defaultextension='.txt', parent=self.parent)

        self.email_boxes_path = self.load_file(
            email_boxes_path, self.email_boxes_data, r"[\d\w\-\.]+@[\d\w]+\.\w+:.+$")

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
            with open(manifest_path, 'r') as file:
                self.manifest_data = json.load(file)
            self.manifest_path = manifest_path
        except (EnvironmentError, TypeError, json.JSONDecodeError):
            return

        self.status_bar.set("Файл загружен: %s" % os.path.basename(manifest_path))

    def proxy_open(self, frame):
        dir_ = (os.path.dirname(self.proxy_path)
                if self.proxy_path is not None else '.')
        proxy_path = askopenfilename(
            title='Proxy',
            initialdir=dir_,
            filetypes=[('Text file (.txt)', '*.txt')],
            defaultextension='.txt', parent=frame)

        self.proxy_path = self.load_file(proxy_path, self.proxy_data)
        frame.destroy()

    def proxy_list_open(self, frame):
        dir_ = (os.path.dirname(self.proxy_path)
                if self.proxy_path is not None else '.')
        proxy_urls_path = askopenfilename(
            title='Proxy URLS',
            initialdir=dir_,
            filetypes=[('Text file (.txt)', '*.txt')],
            defaultextension='.txt', parent=frame)

        self.proxy_urls_path = self.load_file(proxy_urls_path, self.proxy_urls)

    def file_open(self, frame, path, title, collection, regexr=None):
        path_attr = getattr(self, path)
        dir_ = (os.path.dirname(path_attr)
                if path is not None else '.')
        input_path = askopenfilename(
            title=title,
            initialdir=dir_,
            filetypes=[('Text file (.txt)', '*.txt')],
            defaultextension='.txt', parent=frame)

        path_string = self.load_file(input_path, collection, regexr)
        setattr(self, path, path_string)

    def load_file(self, path, data, regexr=None):
        if not path:
            return ''
        try:
            with open(path, 'r', encoding='utf-8') as file:
                for row, item in enumerate(file.readlines()):
                    if regexr and not re.match(regexr, item):
                        self.add_log("Недопустимое значение: {0} в строке {1}".format(item.strip(), row))
                        if not item.endswith("\n"):
                            self.add_log("Отсутствует новая строка (нажмите Enter в конце строки)")
                        continue
                    data.append(item.strip())
        except (EnvironmentError, TypeError):
            return ''

        if data:
            self.add_log("Файл загружен: %s" % os.path.basename(path))
            return path

    def update_clock(self):
        now = time.strftime("%H:%M:%S", time.gmtime(time.time() - self.start_time))
        self.time_stat.set("Времени прошло: %s" % now)
        self.parent.after(1000, self.update_clock)

    def app_quit(self, *ignore):
        self.save_input()
        with open('database/userdata.txt', 'w') as file:
            json.dump(self.userdata, file)

        if self.remove_emails_from_file.get():
            with open(self.email_boxes_path, "w") as file:
                for email in self.email_boxes_data:
                    file.write(email + "\n")

        with open("accounts.txt", "w") as file:
            for account in self.accounts_unbinded:
                login_passwd = account.split(":")[:2]
                login_passwd = ":".join(login_passwd)
                if login_passwd not in self.accounts_binded:
                    file.write(account + "\n")

        self.parent.destroy()

    def check_templates(self):
        for template in (self.login_template, self.passwd_template, self.nickname_template):
            value = template.get()
            if value and "{num}" not in value:
                raise ValueError("Неверно задан шаблон: " + value)


class RegistrationThread(threading.Thread):

    left = 0
    counter = 0
    proxy_limited = 0
    proxy_invalid = 0

    error = False

    lock = threading.Lock()

    is_alive = True

    def __init__(self, frame):
        super().__init__()
        self.daemon = True
        self.client = frame
        self.proxy = None

    def run(self):
        self.set_proxy()
        while RegistrationThread.left > 0:
            with self.lock:
                RegistrationThread.left -= 1
            if self.counter > 0 and self.counter % self.client.accounts_per_proxy.get() == 0:
                self.set_proxy()
            try:
                self.registrate_account()
            except (ProxyError, ConnectionError, Timeout):
                self.client.add_log("Нестабильное соединение: %s" % self.proxy)
                self.set_proxy()
                with self.lock:
                    RegistrationThread.left += 1
                self.proxy_invalid += 1
                self.client.proxies_bad_stat.set("Недействительных прокси: %d" % self.proxy_limited)
            except Exception as error:
                with self.lock:
                    if not RegistrationThread.error:
                        showwarning("Ошибка %s" % error.__class__.__name__, error)
                        logger.critical(traceback.format_exc())
                        RegistrationThread.error = True
                return
            if self.counter % 50 == 0:
                self.client.check_captcha_key()
            self.client.check_captcha_key()

    def registrate_account(self):
        self.client.status_bar.set('Создаю аккаунты, решаю капчи...')
        email, email_password = None, None
        with RegistrationThread.lock:
            try:
                emailbox = self.client.email_boxes_data.pop()
            except IndexError:
                raise Exception("Почты закончились")
            email, email_password = emailbox.split(":")
            if self.client.use_mail_repeatedly.get():
                self.client.email_boxes_data.append(emailbox)
        attempts = 0
        login, password = None, None
        while attempts < 3:
            try:
                login, password, email, email_password = steamregger.create_account_web(
                    email, email_password, proxy=self.proxy)
                break
            except LimitReachedError as err:
                logging.error(err)
                self.client.add_log("Достигнут лимит регистрации аккаунтов: %s. Меняю прокси..." % self.proxy)
                self.proxy_limited += 1
                self.client.proxies_limited_stat.set("Прокси залимичено Steam: %d" % self.proxy_limited)
                self.set_proxy()
                attempts += 1

        logger.info('Аккаунт: %s:%s', login, password)
        self.client.add_log('Аккаунт зарегистрирован (%s, %s, %s)' % (self.proxy, login, password))
        with self.lock:
            self.save_unattached_account(login, password, email, email_password)

        try:
            steam_client = steamregger.login(login, password, self.proxy, self.client,
                                             pass_login_captcha=self.client.pass_login_captcha.get())
        except AuthException as err:
            logger.error(err)
            self.client.add_log("%s: не удается авторизоваться с этого айпи" % str(self.proxy).strip("<>"))
            self.set_proxy()
            return
        except SteamAuthError as err:
            logger.error(err)
            self.client.add_log(err)
            return
        except CaptchaRequired as err:
            logger.error(err)
            self.client.add_log("%s: требуется решить капчу для авторизации в аккаунты" % str(self.proxy).strip("<>"))
            self.set_proxy()
            return

        if self.client.activate_profile.get():
            selection_type = self.client.selection_type.get()
            summary = steamregger.select_profile_data(self.client.statuses, selection_type)
            real_name = steamregger.select_profile_data(self.client.real_names, selection_type)
            country = steamregger.select_profile_data(self.client.countries, selection_type)
            steamregger.activate_account(steam_client, summary, real_name, country)
            steamregger.edit_profile(steam_client)
            self.client.add_log("Профиль активирован: %s:%s" % (login, password))

        avatar = None
        if self.client.avatars:
            if self.client.selection_type.get() == SelectionType.RANDOM:
                avatar = random.choice(self.client.avatars)
            elif self.client.selection_type.get() == SelectionType.CONSISTENT:
                avatar = self.client.avatars.pop(0)

            match = re.match(r"https?://.+", str(avatar))
            if match is not None:  # str(avatar) if avatar is a link
                avatar_link = match.group()
                avatar = requests.get(avatar_link).content
                try:
                    self.client.avatars.remove(avatar_link)
                except ValueError:
                    pass
                self.client.avatars.append(avatar)

            steamregger.upload_avatar(steam_client, avatar)

        if self.client.add_money_to_account.get():
            self.add_money(login)

        if self.client.free_games.get() or self.client.paid_games.get():
            steam_client.session.get("http://store.steampowered.com")
        if self.client.free_games.get():
            self.add_free_games(steam_client)
        if self.client.paid_games.get():
            self.purchase_games(steam_client)

        self.counter += 1
        self.client.accounts_registrated_stat.set("Аккаунтов зарегистрировано: %d" % self.counter)
        self.client.accounts_registrated_stat.set("Осталось аккаунтов зарегистрировать : %d" %
                                                  (self.client.new_accounts_amount.get() - self.counter))
        Account = namedtuple("Account", "login password email email_password")
        account = Account(login, password, email, email_password)
        self.client.accounts.put(account)

    def set_proxy(self):
        if self.proxy is not None:
            self.proxy.close()
        timeout = 120
        try:
            proxy = self.client.reg_proxies.get(timeout=timeout)
            if proxy is None:
                raise Empty
        except Empty:
            raise Exception("Валидные прокси закончились")

        self.client.add_log("Regger: " + str(proxy).strip("<>"))
        self.proxy = proxy

    def add_free_games(self, steam_client):
        appids = self.client.free_games.get().replace(" ", "").split(",")
        data = {
            'action': 'add_to_cart',
            'sessionid': steam_client.session.cookies.get('sessionid', domain='store.steampowered.com')
        }
        for subid in appids:
            data['subid'] = int(subid)
            steam_client.session.post('https://store.steampowered.com/checkout/addfreelicense', data=data)

    def purchase_games(self, steam_client):
        appids = self.client.paid_games.get().replace(" ", "").split(",")
        sessionid = steam_client.session.cookies.get('sessionid', domain='store.steampowered.com')
        data = {"action": "add_to_cart", "sessionid": sessionid, "snr": "1_5_9__403"}
        for appid in appids:
            data["subid"] = int(appid)
            steam_client.session.post("https://store.steampowered.com/cart/", data=data)
        resp = steam_client.session.get("ps://store.steampowered.com/checkout/?purchasetype=self",
                                        params={"purchasetype": "self"})
        cart_id = re.search(r"id=\"shopping_cart_gid\" value=\"(\d+)\">", resp.text).group(1)
        data = {
            "gidShoppingCart": cart_id,
            "gidReplayOfTransID": -1,
            "PaymentMethod": "steamaccount",
            "abortPendingTransactions": 0,
            "bHasCardInfo": 0,
            "Country": "RU",
            "bIsGift": 0,
            "GifteeAccountID": 0,
            "ScheduledSendOnDate": 0,
            "bSaveBillingAddress": 1,
            "bUseRemainingSteamAccount": 1,
            "bPreAuthOnly": 0,
            "sessionid": sessionid
        }
        resp = steam_client.session.post("https://store.steampowered.com/checkout/inittransaction/", data=data).json()
        trans_id = resp["transid"]
        steam_client.session.post("https://store.steampowered.com/checkout/finalizetransaction/",
                                  data={"transid": trans_id})

    def add_money(self, login):
        wallet = pyqiwi.Wallet(token=self.client.qiwi_api_key.get())
        wallet.send(pid="25549", recipient=login, amount=int(self.client.money_to_add.get()))

    @staticmethod
    def save_unattached_account(login, password, email, email_password):
        with open('accounts(login,pass,email).txt', 'a+') as file:
            file.write('%s:%s:%s:%s\n' % (login, password, email, email_password))

        with open(r'accounts(login,pass).txt' % login, 'w') as file:
            file.write('%s:%s\n' % (login, password))

        with open(r'новые_аккаунты/%s.txt' % login, 'w') as file:
            file.write('%s:%s\nEmail: %s:%s' % (login, password, email, email_password))


class Binder(threading.Thread):

    lock = threading.Lock()

    binded_counter = 0
    binding_total = 0
    numbers_ordered_counter = 0
    numbers_failed_counter = 0

    error = False

    def __init__(self, frame, sms_service, amount):
        super().__init__()
        self.client = frame
        self.amount = amount
        self.counter = self.amount
        self.sms_service = sms_service
        self.number = None
        self.proxy = None
        self.used_codes = []

    def run(self):
        try:
            self.run_as_handled()
        except Exception as err:
            with self.lock:
                if not self.error:
                    showwarning(f"Ошибка {err.__class__.__name__}", err)
                    logger.critical(traceback.format_exc())
                    self.error = True
            if self.number:  # if the operation has successfully finished
                self.sms_service.set_operation_ok(self.number['tzid'], self.number['time'])
            return

    def run_as_handled(self):
        self.client.set_proxy()
        self.client.status_bar.set("Привязываю мобильный аутентификатор")
        pack = []
        while True:
            with self.lock:
                self.fill_pack(pack)
            if not pack:
                return
            for account in pack:
                while True:
                    try:
                        self.client.bind_account(account)
                        break
                    except (ProxyError, ConnectionError, Timeout):
                        self.client.add_log("Нестабильное соединение: %s" % self.proxy)
                        self.client.set_proxy()
                self.client.onlinesim_balance_stat.set("Баланс SIM сервиса: %s" % self.sms_service.get_balance())
                with self.lock:
                    self.fill_pack(pack)
                self.client.status_bar.set("Привязываю мобильный аутентификатор")
                while True:
                    try:
                        account = pack.pop()
                    except IndexError:
                        break
                    try:
                        self.client.bind_account(account)
                        break
                    except (SteamAuthError, CaptchaRequired, AuthException) as e:
                        with open("accounts_failed.txt", "a+"):
                            f.write("{}:{}:{}:{}\n".format(
                                account.login, account.password, account.email, account.email_password))
                        self.client.add_log("Ошибка: %s" % e)
                        continue
                    except (ProxyError, ConnectionError, Timeout):
                        self.client.add_log("Нестабильное соединение: %s" % self.proxy)
                        self.client.set_proxy()
                    self.client.onlinesim_balance_stat.set("Баланс SIM сервиса: %s" % self.sms_service.get_balance())

    def fill_pack(self, pack):
        amount = self.amount
        accounts_for_binding = len(self.client.old_accounts)
        if self.client.autoreg.get():
            accounts_for_binding = self.client.new_accounts_amount.get()
        timeout = 90
        if not self.client.autoreg.get():
            timeout = 0
        for _ in range(accounts_for_binding):
            while amount:
                try:
                    account = self.client.accounts.get(timeout=timeout)
                    pack.append(account)
                    amount -= 1
                except Empty:
                    if not RegistrationThread.is_alive:
                        raise Empty("accounts for mobile binding have been depleted")

    def bind_account(self, account):
        login, password, email, email_password = account.login, account.password, account.email, account.email_password
        logger.info('Аккаунт: %s:%s', login, password)
        insert_log = self.log_wrapper(login)
        insert_log('Логинюсь в аккаунт')
        try:
            steam_client = steamregger.mobile_login(login, password, self.proxy, email, email_password,
                                                    pass_login_captcha=self.client.pass_login_captcha.get())
        except AuthException as err:
            logger.error(err)
            self.client.add_log("%s: не удается авторизоваться с этого айпи" % str(self.proxy).strip("<>"))
            self.set_proxy()
            return
        except SteamAuthError as err:
            if "К аккаунту уже привязан Guard" in str(err):
                self.client.accounts_binded.append(login + ":" + password)
            insert_log(err)
            return
        except CaptchaRequired as err:
            logger.error(err)
            insert_log("%s: требуется решить капчу для авторизации в аккаунты" % str(self.proxy).strip("<>"))
            self.set_proxy()
            return
        except imaplib.IMAP4.error as err:
            insert_log("Ошибка почты %s" % err)
            return

        if self.counter == self.amount:
            self.get_new_number()
            self.counter = 0

        insert_log('Номер: ' + self.number['number'])
        sms_code, mobguard_data = self.add_authenticator(insert_log, steam_client, email, email_password)
        mobguard_data['account_password'] = password
        offer_link = steamregger.fetch_tradeoffer_link(steam_client)
        self.save_attached_account(mobguard_data, account, self.number['number'], offer_link)

        self.counter += 1

        self.client.binding_quota.set(self.client.binding_quota.get() - 1)
        if not self.client.autoreg.get() and self.client.activate_profile.get():
            selection_type = self.client.selection_type.get()
            summary = steamregger.select_profile_data(self.client.statuses, selection_type)
            real_name = steamregger.select_profile_data(self.client.real_names, selection_type)
            country = steamregger.select_profile_data(self.client.countries, selection_type)
            steamregger.activate_account(steam_client, summary, real_name, country)
            steamregger.edit_profile(steam_client)
            self.client.add_log("Профиль активирован: %s:%s" % (login, password))
        insert_log('Guard успешно привязан')
        self.binded_counter += 1
        self.client.accounts_binded_stat.set("Аккаунтов привязано: %d" % self.binded_counter)
        self.client.accounts_binded_stat.set("Осталось аккаунтов привязать: %d" % (self.binding_total - self.binded_counter))
        self.client.accounts_binded.append(login + ":" + password)

    def add_authenticator(self, insert_log, steam_client, email, email_password):
        steamregger.is_phone_attached(steam_client)
        insert_log('Делаю 3 попытки установить Guard...')
        while True:
            success = steamregger.addphone_request(steam_client, self.number['number'])
            if not success:
                insert_log("прокси забанен Steam-ом")
                self.set_proxy()
                continue
            break
        insert_log('Отправляю запрос на получение почты')
        success = steamregger.fetch_email_code(email, email_password, steam_client)
        if not success:
            raise SteamAuthError("Не удается получить письмо")
        success = steamregger.email_confirmation(steam_client)
        if not success:
            raise SteamAuthError("Не удалсоь подтвердить почту")

        insert_log('Делаю запрос Steam на добавление аутентификатора...')
        mobguard_data = steamregger.add_authenticator_request(steam_client)
        steamregger.is_phone_attached(steam_client)
        insert_log('Жду SMS код до 2 минут...')
        attempts = 0
        sms_code = None
        while attempts < 24:
            try:
                if self.number['is_repeated']:
                    self.sms_service.request_repeated_number_usage(self.number['tzid'])
                attempts += 1
                sms_code, time_left = self.sms_service.get_sms_code(self.number['tzid'])
                if sms_code and sms_code not in self.used_codes:
                    self.used_codes.append(sms_code)
                    break
                time.sleep(5)
            except (OnlineSimError, SmsActivateError) as err:
                insert_log("Ошибка onlinesim: %s" % err)
                insert_log('Новый номер: ' + self.number['number'])
                raise SteamAuthError

            if not sms_code and time_left == 0:
                insert_log("Закончилось время аренды номера. Меняю номер")
                self.get_new_number(self.number['tzid'])
                return self.add_authenticator(insert_log, steam_client, email, email_password)

            if not sms_code:
                insert_log("Не доходит смс. Запрашиваю смс повторно")
                attempts += 1
                continue
            insert_log("SMS получено: %s" % sms_code)
            success = steamregger.checksms_request(steam_client, sms_code)
            if not success:
                insert_log("Код неверен. Пробую снова запросить sms код")
                attempts += 1
                continue
            else:
                break

        self.number['is_repeated'] = True

        logger.info("mobguard data: %s", mobguard_data)
        return sms_code, mobguard_data

    def get_new_number(self, tzid=0):
        if tzid:
            self.sms_service.set_operation_ok(tzid, self.number['time'])
            self.used_codes.clear()
        is_repeated = False
        self.numbers_ordered_counter += 1
        self.client.numbers_used_stat.set("Использовано номеров: %s" % self.numbers_ordered_counter)
        tzid, number = self.sms_service.get_number(country=self.client.number_countries[self.client.country_code.get()])
        self.number = {'tzid': tzid, 'number': number, 'is_repeated': is_repeated, 'time': int(time.time())}

    def save_attached_account(self, mobguard_data, account, number, offer_link):
        if self.client.autoreg.get():
            accounts_dir = 'новые_аккаунты'
        else:
            accounts_dir = 'загруженные_аккаунты'

        if self.client.fold_accounts.get():
            accounts_dir = os.path.join(accounts_dir, account.login)
            os.makedirs(accounts_dir)

        steamid = mobguard_data['Session']['SteamID']
        txt_path = os.path.join(accounts_dir, account.login + '.txt')
        mafile_path = os.path.join(accounts_dir, account.login + '.maFile')
        binding_date = datetime.date.today()
        revocation_code = mobguard_data['revocation_code']
        with open(txt_path, 'w', encoding='utf-8') as file:
            file.write('{account.login}:{account.password}\nДата привязки Guard: {binding_date}\nНомер: {number}\n'
                       'SteamID: {steamid}\nRCODE: {revocation_code}\nТрейд ссылка: {offer_link}\n'
                       'Email: {account.email}\nEmail password: {account.email_password}'.format(**locals()))

        with open('accounts_guard.txt', 'a+') as file:
            file.write('%s:%s:%s:%s\n' % (account.login, account.password, account.email, account.email_password))

        if self.client.import_mafile.get():
            sda_path = os.path.join(os.path.dirname(self.client.manifest_path), account.login + '.maFile')
            data = {
                "encryption_iv": None,
                "encryption_salt": None,
                "filename": account.login + '.maFile',
                "steamid": int(steamid)
            }
            self.client.manifest_data["entries"].append(data)
            with open(self.client.manifest_path, 'w') as f1, open(sda_path, 'w') as f2:
                json.dump(self.client.manifest_data, f1)
                json.dump(mobguard_data, f2, separators=(',', ':'))

        with open(mafile_path, 'w') as file:
            json.dump(mobguard_data, file, separators=(',', ':'))

    def set_proxy(self):
        if self.proxy is not None:
            self.proxy.close()
        timeout = 120
        try:
            proxy = self.client.bind_proxies.get(timeout=timeout)
            if proxy is None:
                raise Empty
        except Empty:
            raise Exception("Валидные прокси закончились")

        self.client.add_log("Binder: " + str(proxy).strip("<>"))
        self.proxy = proxy

    def log_wrapper(self, login):
        def insert_log(text):
            self.client.add_log('%s (%s)' % (text, login))
        return insert_log


if __name__ == '__main__':
    root = Tk()
    window = MainWindow(root)
    
    steamregger = SteamRegger(window)

    root.iconbitmap('database/app.ico')
    root.title('Steam Auto Authenticator v.3')
    root.protocol("WM_DELETE_WINDOW", window.app_quit)
    root.mainloop()
    