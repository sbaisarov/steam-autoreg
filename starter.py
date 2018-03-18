import logging
import os


def confirm_packages():
    from pkgutil import iter_modules
    installed_modules = [item[1] for item in iter_modules()]
    required_modules = {
        'bs4': 'bs4',
        'rsa': 'rsa',
        'websocket': 'websocket-client',
        'requests': 'https://github.com/Shamanovski/requests/archive/master.zip',
        'execjs': 'https://github.com/Shamanovski/PyExecJS/archive/master.zip'
    }
    for module_name, module in required_modules.items():
        if module_name not in installed_modules:
            os.system('pip install %s' % module)

    # required_modules = {'steam-user', 'sync-request', 'steamcommunity', 'winston'}
    # try:
    #     node_modules = set(os.listdir("node_modules"))
    # except FileNotFoundError:
    #     node_modules = set()
    # if not required_modules.issubset(node_modules):
    #     os.system("npm i")


logging.getLogger("requests").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
handler = logging.FileHandler('database/logs.txt', 'w', encoding='utf-8')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

confirm_packages()

import user_interface
