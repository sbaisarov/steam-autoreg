from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import showwarning
import logging
import urllib
import requests
import os
import datetime
import uuid
import json
import time
import traceback
import threading

from websocket import create_connection

from steampy.guard import generate_one_time_code
import steampy.utils
from steamreg import *
from sms_services import *

logging.getLogger("requests").setLevel(logging.ERROR)
logger = logging.getLogger()
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
handler = logging.FileHandler('reger.log', 'w', encoding='utf-8')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)



class MainWindow():

    def __init__(self, parent):
        self.parent = parent
        frame = Frame(self.parent)
        success = self._authorize_user()
        if not success:
            self.license = StringVar()
            license_key_label = Label(frame, text='Введите ключ активации программы:')
            license_key_label.grid(row=0, column=0, pady=5, sticky=W)
            self.license_key_entry = Entry(frame, textvariable=self.license)
            self.license_key_entry.grid(row=0, column=1, pady=5, padx=5, sticky=W)
            check_license_bttn = Button(frame, text='Проверить лицензию',
                                        command=lambda: self.check_license(frame),
                                        relief=GROOVE)
            check_license_bttn.grid(sticky=W, padx=20, pady=5)
            frame.grid(row=0, column=0)
            return

        self.filename = None
        self.manifest = None
        self.autoreg = IntVar()
        self.import_mafile = IntVar()
        self.accounts = []
        self.steamreg = SteamRegger()

        menubar = Menu(parent)
        parent['menu'] = menubar
        menubar.add_command(label="Указать данные от аккаунтов", command=self.file_open)
        menubar.add_command(label="Указать manifest", command=self.manifest_open)

        self.onlinesim_api_key = StringVar()
        self.smsactivate_api_key = StringVar()
        self.status_bar = StringVar()
        self.numbers_per_account = StringVar()

        onlinesim_apikey_label = Label(frame, text='onlinesim.ru api key:')
        onlinesim_apikey_label.grid(row=0, column=0, pady=5, sticky=W)
        onlinesim_apikey_entry = Entry(frame, textvariable=self.onlinesim_api_key)
        onlinesim_apikey_entry.grid(row=0, column=1, pady=5, padx=5, sticky=W)

        ctr_label = Label(frame, text='Количество аккаунтов на 1 номер:')
        ctr_label.grid(row=1, column=0, pady=5)
        ctr_entry = Entry(frame, textvariable=self.numbers_per_account, width=5)
        ctr_entry.grid(row=1, column=1, pady=5, padx=5, sticky=W)

        autoreg_checkbutton = Checkbutton(frame, text='Создавать новые аккаунты',
                                          variable=self.autoreg)
        autoreg_checkbutton.grid(row=2, column=0, sticky=W)
        mafile_checkbutton = Checkbutton(frame, text='Импортировать maFile в SDA',
                                         variable=self.import_mafile)
        mafile_checkbutton.grid(row=2, column=1, pady=3)

        start_button = Button(frame, text='Начать', command=self.run_process,
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


    def run_process(self):
        onlinesim_api_key = self.onlinesim_api_key.get()
        if not onlinesim_api_key:
            showwarning("Ошибка", "Не указан api ключ для onlinesim.ru", parent=self.parent)
            return
        if not self.filename and not self.autoreg:
            showwarning("Ошибка", "Не указан файл с данными от аккаунтов", parent=self.parent)
            return
        try:
            numbers_per_account = int(self.numbers_per_account.get())
            if numbers_per_account <= 0:
                raise ValueError
        except (TypeError, ValueError):
            showwarning("Ошибка", "Введите корректное число аккаунтов, "
                        "связанных с 1 номером.", parent=self.parent)
            return

        sms_service = OnlineSimApi(onlinesim_api_key)
        ctr = 0
        is_repeated = False
        try:
            tzid = sms_service.request_new_number()
            self.status_bar.set('Запрашиваю номер...')
            number = sms_service.get_number(tzid)
            self.log_box.insert(END, 'Номер: ' + number)
            for login, passwd in self.accounts:
                logger.info(login + ' ' + passwd)
                self.log_box.insert(END, 'Привязываю Guard к аккаунту: ' + login)
                self.status_bar.set('Логинюсь в аккаунт...')
                steam_client = self.steamreg.mobile_login(login, passwd)

                if ctr == numbers_per_account:
                    tzid, number, is_repeated, ctr = self.get_new_number(sms_service, tzid)

                while True:
                    self.status_bar.set('Делаю запрос Steam на добавление номера...')
                    is_number_valid = self.steamreg.steam_addphone_request(steam_client, number)
                    if not is_number_valid:
                        self.log_box.insert(END, 'Стим сообщил о том, что номер не подходит')
                        tzid, number, is_repeated, ctr = self.get_new_number(sms_service, tzid)
                        continue
                    self.status_bar.set('Жду SMS код...')
                    sms_code = sms_service.get_sms_code(tzid, is_repeated=is_repeated)
                    is_repeated = True
                    if not sms_code:
                        self.log_box.insert(END, 'Не доходит SMS. Меняю номер...')
                        tzid, number, is_repeated, ctr = self.get_new_number(sms_service, tzid)
                        continue
                    success = self.steamreg.steam_checksms_request(steam_client, sms_code)
                    if not success:
                        raise Exception('Неверный SMS код. Обратись ко мне с этой ошибкой')

                    self.status_bar.set('Делаю запрос на привязку гуарда...')
                    mobguard_data = self.steamreg.steam_add_authenticator_request(steam_client)
                    self.status_bar.set('Жду SMS код...')
                    sms_code = sms_service.get_sms_code(tzid, is_repeated=is_repeated)
                    if not sms_code:
                        self.log_box.insert(END, 'Не доходит SMS. Меняю номер...')
                        tzid, number, is_repeated, ctr = self.get_new_number(sms_service, tzid)
                        continue
                    success = self.steamreg.steam_finalize_authenticator_request(
                                steam_client, mobguard_data, sms_code)
                    if not success:
                        raise Exception('Неверный SMS код. Обратись ко мне с этой ошибкой')
                    break

                self.save_data(mobguard_data)
                self.log_box.insert(END, 'Guard успешно привязан: ' + login)

                ctr += 1

        except OnlineSimError as err:
            showwarning("Ошибка onlinesim.ru", err, parent=self.parent)
        except SteamAuthError as err:
            self.log_box.insert(END, err)
        except SteamCaptchaError as err:
            showwarning('Ошибка', err)
        except Exception:
            showwarning('Ошибка', traceback.format_exc())
        finally:
            self.status_bar.set('Готов...')


    def _get_new_number(self, sms_service, tzid):
        ctr = 0
        is_repeated = False
        sms_service.set_operation_ok(tzid)
        sms_service.used_codes.clear()
        self.status_bar.set('Запрашиваю новый номер...')
        tzid = sms_service.request_new_number()
        number = sms_service.get_number(tzid)
        self.log_box.insert(END, 'Новый номер: ' + number)
        return tzid, number, is_repated, ctr

    @staticmethod
    def _authorize_user():
        key = ''
        if os.path.exists('steamreg.key'):
            with open('steamreg.key', 'r') as f:
                key = f.read()
                resp = requests.post('http://127.0.0.1:3000',
                             data={
                                     'key': key,
                                     'uuid': uuid.uuid1()
                             }
               ).json()

        if not key or not resp['success']:
            return False

        return True

    def check_license(self, frame):
        key = self.license_key_entry.get()
        resp = requests.post('http://127.0.0.1:3000',
                             data={
                                     'key': key,
                                     'uuid': uuid.uuid1()
                             }
               ).json()

        print(resp)
        if not resp['success']:
            showwarning('Ошибка', 'Неверный ключ либо попытка активации с неавторизованного устройства')
            return

        with open('steamreg.key', 'w') as f:
            f.write(key)
        top = Toplevel(frame)
        top.title("Успешно!")
        top.geometry('250x25')
        msg = Message(top, text='Программа активирована.', aspect=1000)
        msg.grid()

        self.__init__(root)


    @staticmethod
    def create_thread(func):
        if len(threading.enumerate()) == 1:
            threading.Thread(target=func).start()


    def save_data(self, mobguard_data):
        steamid = mobguard_data['Session']['SteamID']
        mafile_path = os.path.join(os.path.dirname(self.filename), steamid + '.maFile')
        with open(mafile_path, 'w') as f:
            json.dump(mobguard_data, f)


    def file_open(self):
        dir = (os.path.dirname(self.filename)
               if self.filename is not None else '.')
        filename = askopenfilename(
                    title='логин:пасс аккаунтов',
                    initialdir=dir,
                    filetypes=[('Text file', '*.txt')],
                    defaultextension='.txt', parent=self.parent)
        if filename:
            return self.load_file(filename)


    def load_file(self, filename):
        self.filename = filename
        self.accounts.clear()
        try:
            with open(self.filename, 'r') as f:
                for acc_item in f.readlines():
                    acc_data = acc_item.rstrip().split(':')
                    self.accounts.append(acc_data)

            self.status_bar.set('Загружен файл: {}'.format(
                                os.path.basename(self.filename)))
        except EnvironmentError as err:
            showwarning("Ошибка", "Не удалось загрузить: {0}:\n{1}".format(
                                    self.filename, err), parent=self.parent)


    def manifest_open(self):
        dir_ = (os.path.dirname(self.manifest)
               if self.manifest is not None else '.')
        manifest = askopenfilename(
                    title='SDA manifest',
                    initialdir=dir_,
                    filetypes=[('manifest', '*.json')],
                    defaultextension='.json', parent=self.parent)
        if manifest:
            return self.load_manifest(manifest)

    def load_manifest(self, manifest):
        self.manifest = manifest
        with open(manifest, 'r') as f:
            self.manifest_data = json.load(f)


root = Tk()
window = MainWindow(root)
root.title('Steam Auto Authenticator v0.1')
root.mainloop()
