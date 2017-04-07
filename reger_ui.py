from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import showwarning
import logging
import os
import datetime
import json
import traceback
import threading

from steamreg import *
from sms_services import *

# logging.basicConfig(filename='logs.txt',
#                    level=logging.DEBUG,
#                    format='%(asctime)s - %(levelname)s - %(message)s')


class MainWindow():

    def __init__(self, parent):

        self.filename = None
        self.mailboxes_path = None
        self.accounts = []
        self.mailboxes = []
        self.parent = parent
        self.steamreg = SteamRegger()

        frame = Frame(self.parent)
        menubar = Menu(parent)
        parent['menu'] = menubar
        menubar.add_command(label="Указать данные от аккаунтов", command=self.file_open)
        menubar.add_command(label="Указать данные от почт", command=self.mailboxes_file_open)

        self.onlinesim_api_key = StringVar()
        self.smsactivate_api_key = StringVar()
        self.status_bar = StringVar()
        self.numbers_per_account = StringVar()

        onlinesim_apikey_label = Label(frame, text='onlinesim.ru api key:')
        onlinesim_apikey_label.grid(row=0, column=0, pady=5, sticky=W)
        onlinesim_apikey_entry = Entry(frame, textvariable=self.onlinesim_api_key)
        onlinesim_apikey_entry.grid(row=0, column=1, pady=5, padx=5, sticky=W)
        start_binding_onlinesim_bttn = Button(frame, text='Начать',
                                              command=lambda: self.create_thread(self.start_binding_onlinesim))
        start_binding_onlinesim_bttn.grid(row=1, column=0, pady=5, sticky=W, padx=10)

        smsactivate_apikey_label = Label(frame, text='sms-activate.ru api key:')
        smsactivate_apikey_label.grid(row=2, column=0, pady=5, sticky=W)
        smsactivate_apikey_entry = Entry(frame, textvariable=self.smsactivate_api_key)
        smsactivate_apikey_entry.grid(row=2, column=1, pady=5, padx=5, sticky=W)
        start_binding_smsactivate_bttn = Button(frame, text='Начать',
                                                command=lambda: self.create_thread(self.start_binding_smsactivate))
        start_binding_smsactivate_bttn.grid(row=3, column=0, pady=5, sticky=W, padx=10)

        ctr_label = Label(frame, text='Количество аккаунтов на 1 номер:')
        ctr_label.grid(row=4, column=0, pady=5)
        ctr_entry = Entry(frame, textvariable=self.numbers_per_account, width=5)
        ctr_entry.grid(row=4, column=1, pady=5, padx=5, sticky=W)

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


    def start_binding_onlinesim(self):
        onlinesim_api_key = self.onlinesim_api_key.get()
        if not onlinesim_api_key:
            showwarning("Ошибка", "Не указан api ключ для onlinesim.ru", parent=self.parent)
            return
        if not self.filename:
            showwarning("Ошибка", "Не указан файл с данными от аккаунтов", parent=self.parent)
            return
        if not self.manifest_path:
            showwarning("Ошибка", "Не указан manifest файл от SDA", parent=self.parent)
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
            for acc_data in self.accounts:
                login, passwd, email, email_passwd = acc_data
                self.log_box.insert(END, 'Привязываю Guard к аккаунту: ' + login)
                self.status_bar.set('Логинюсь в аккаунт...')
                steam_client = self.steamreg.mobile_login(login, passwd, email, email_passwd)

                if ctr == numbers_per_account:
                    sms_service.set_operation_ok(tzid)
                    sms_service.used_codes.clear()
                    self.status_bar.set('Запрашиваю новый номер...')
                    tzid = sms_service.request_new_number()
                    number = sms_service.get_number(tzid)
                    self.log_box.insert(END, 'Новый номер: ' + number)
                    ctr = 0
                    is_repeated = False

                while True:
                    self.status_bar.set('Делаю запрос на добавление номера...')
                    self.steamreg.steam_addphone_request(steam_client, number)
                    self.status_bar.set('Жду SMS код...')
                    sms_code = sms_service.get_sms_code(tzid, is_repeated=is_repeated)
                    is_repeated = True
                    if not sms_code:
                        self.log_box.insert(END, 'Не доходит SMS. Делаю новый запрос...')
                        continue
                    success = self.steamreg.steam_checksms_request(steam_client, sms_code)
                    if success:
                        break
                    self.log_box.insert(END, 'SMS код не подошел либо не был получен, '
                                             'делаю повторный запрос...')


                while True:
                    self.status_bar.set('Делаю запрос на привязку аутентификатора...')
                    time.sleep(3)
                    mobguard_data = self.steamreg.steam_add_authenticator_request(steam_client)
                    self.status_bar.set('Жду SMS код...')
                    sms_code = sms_service.get_sms_code(tzid, is_repeated=is_repeated)
                    if not sms_code:
                        self.log_box.insert(END, 'Не доходит SMS. Делаю новый запрос...')
                        continue
                    success = self.steamreg.steam_finalize_authenticator_request(
                                steam_client, mobguard_data, sms_code)
                    if success:
                        break
                    self.log_box.insert(END, 'СМС код не подошел либо не был получен, '
                                             'делаю повторный запрос...')

                self.save_data(acc_data, number, mobguard_data)
                ctr += 1

        except OnlineSimError as err:
            showwarning("Ошибка onlinesim.ru", err, parent=self.parent)
            return
        except SteamAuthError as err:
            self.log_box.insert(END, err)
        except SteamCaptchaError as err:
            showwarning('Ошибка', err)
            return
        except Exception:
            showwarning('Ошибка', traceback.format_exc())
            return
        finally:
            self.status_bar.set('Готов...')

    def start_binding_smsactivate(self):
        smsactivate_api_key =  self.smsactivate_api_key.get()
        if not smsactivate_api_key:
            showwarning("Ошибка", "Не указан api ключ для sms-activate.ru", parent=self.parent)
            return
        if not self.filename:
            showwarning("Ошибка", "Не указан файл с данными от аккаунтов", parent=self.parent)
            return
        if not self.manifest_path:
            showwarning("Ошибка", "Не указан manifest файл от SDA", parent=self.parent)
            return
        sms_service = SmsActivateApi(smsactivate_api_key)
        ctr = 0
        try:
            numbers_per_account = int(self.numbers_per_account.get())
            if numbers_per_account <= 0:
                raise ValueError
        except (ValueError, TypeError):
            showwarning("Ошибка", "Введите корректное число аккаунтов, "
                        "связанных с 1 номером.", parent=self.parent)
            return

        status = '1'
        self.status_bar.set('Запрашиваю номер...')
        try:
            id, number = sms_service.get_number()
            self.log_box.insert(END, 'Номер: ' + number)
            for acc_data in self.accounts:
                login, passwd, email, email_passwd = acc_data
                # login, passwd = self.steamreg.create_account()
                # print(login, passwd)
                self.status_bar.set('Привязываю Guard к аккаунту: ' + login)
                self.status_bar.set('Логинюсь в аккаунт...')
                steam_client = self.steamreg.mobile_login(login, passwd, email, email_passwd)
                if ctr == numbers_per_account:
                    sms_service.set_status(id, '6')
                    self.status_bar.set('Запрашиваю новый номер...')
                    id, number = sms_service.get_number()
                    self.log_box.insert(END, 'Новый номер: ' + number)
                    status = '1'
                    ctr = 0

                while True:
                    self.status_bar.set('Делаю запрос на добавление номера...')
                    self.steamreg.steam_addphone_request(steam_client, number)
                    sms_service.set_status(id, status)
                    self.status_bar.set('Жду SMS код...')
                    sms_code = sms_service.get_status(id)
                    status = '3'
                    if not sms_code:
                        self.log_box.insert(END, 'Не доходит SMS. Делаю новый запрос...')
                        continue
                    success = self.steamreg.steam_checksms_request(steam_client, sms_code)
                    if success:
                        break
                    self.log_box.insert(END, 'СМС код не подошел, '
                                             'делаю повторный запрос...')

                while True:
                    self.status_bar.set('Делаю запрос на привязку аутентификатора...')
                    time.sleep(3)
                    mobguard_data = self.steamreg.steam_add_authenticator_request(steam_client)
                    sms_service.set_status(id, status)
                    self.status_bar.set('Жду SMS код...')
                    sms_code = sms_service.get_status(id, sms_code_prev=sms_code)
                    if not sms_code:
                        self.log_box.insert(END, 'Не доходит SMS. Делаю новый запрос...')
                        continue
                    success = self.steamreg.steam_finalize_authenticator_request(
                                steam_client, mobguard_data, sms_code)
                    if success:
                        break
                    self.log_box.insert(END, 'СМС код не подошел, '
                                             'делаю повторный запрос...')

                self.save_data(acc_data, number, mobguard_data)
                ctr += 1
        except SteamAuthError as err:
            self.log_box.insert(END, err)
        except SteamCaptchaError as err:
            showwarning('Ошибка', err)
            return
        except SmsActivateError as err:
            showwarning("Ошибка sms-activate.ru", err, parent=self.parent)
            return
        except Exception:
            showwarning('Ошибка', traceback.format_exc())
            return
        finally:
            self.status_bar.set('Готов...')


    @staticmethod
    def create_thread(func):
        if len(threading.enumerate()) == 1:
            threading.Thread(target=func).start()


    def save_data(self, acc_data, number, mobguard_data):
        login = acc_data[0]
        #acc_dir = os.path.join(os.path.dirname(self.filename), login)
        #os.makedirs(acc_dir)
        #txt_path = os.path.join(acc_dir, login + '.txt')
        dir = os.path.dirname(self.manifest_path)
        steamid = mobguard_data['Session']['SteamID']
        mafile_path = os.path.join(dir, steamid + '.maFile')
        data = {
        "encryption_iv": None,
        "encryption_salt": None,
        "filename": steamid + '.maFile',
        "steamid": int(steamid)
        }
        self.manifest_data["entries"].append(data)
        with open(mafile_path, 'w') as f1, open(self.manifest_path, 'w') as f2:
            #f1.write('{}:{}:{}:{}\nДата привязки Guard: {}\nPhone: {}'.format(
                     #*acc_data, str(datetime.date.today()), number))
            json.dump(mobguard_data, f1)
            json.dump(self.manifest_data, f2)
        self.log_box.insert(END, 'Guard успешно привязан: ' + login)


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
                for item in f.readlines():
                    acc_data = item.rstrip().split(':')
                    if len(acc_data) == 2:
                        acc_data += ['', '']
                    self.accounts.append(acc_data)

            self.parent.title('Accounts - {}'.format(
                              os.path.basename(self.filename)))
            self.status_bar.set('Загружен файл: {}'.format(
                                os.path.basename(self.filename)))
        except EnvironmentError as err:
            showwarning("Ошибка", "Не удалось загрузить: {0}:\n{1}".format(
                                    self.filename, err), parent=self.parent)


    def mailboxes_file_open(self):
        dir = (os.path.dirname(self.mailboxes_path)
               if self.mailboxes_path is not None else '.')
        mailboxes_path = askopenfilename(
                    title='логин:пасс почт',
                    initialdir=dir,
                    filetypes=[('Text file', '*.txt')],
                    defaultextension='.txt', parent=self.parent)
        if mailboxes_path:
            return self.mailboxes_path(mailboxes_path)


    def load_mailboxes(self, mailboxes_path):
        self.mailboxes_path = mailboxes_path
        self.mailboxes.clear()
        try:
            with open(mailboxes_path, 'r') as f:
                for item in f.readlines():
                    email_data = item.rstrip().split(':')
                    self.mailboxes.append(acc_data)
            self.parent.title('Accounts - {}'.format(
                              os.path.basename(self.mailboxes_path)))
            self.status_bar.set('Загружен файл: {}'.format(
                                os.path.basename(self.mailboxes_path)))
        except EnvironmentError as err:
            showwarning("Ошибка", "Не удалось загрузить: {0}:\n{1}".format(
                        self.mailboxes_path, err), parent=self.parent)

root = Tk()
window = MainWindow(root)
root.title('Mobile Guard Authenticator')
root.mainloop()


'http://steamcommunity.com/actions/AddFriendAjax'

sessionID:0f5bbfcfedfb1b3c4e7f8458
steamid:76561198218640297
accept_invite:0
