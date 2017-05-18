import json
import logging
import shelve
import requests

from flask import Flask, request

# disable flask and requests info logs
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)

logger = logging.getLogger()
logger.setLevel(level=logging.INFO)
file_handler = logging.FileHandler('logs.txt', 'a', encoding='utf-8')
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

app = Flask(__name__)
db = shelve.open('clients', writeback=True)

@app.route('/', methods=['POST'])
def handle_request():
    with open('keys.txt', 'r') as f:
        keys = [i.rstrip() for i in f.readlines()]

    success = False
    data = {key: value for key, value in request.form.items()}
    ip = request.remote_addr
    ip = '188.0.188.236'
    key = data['key']
    if key in keys:
        if not db.get(key, None):
            update_database(data, key, ip)
            success = True
            logger.info('VALID KEY. Added to the database: %s', data)
        else:
            success = check_device(data, key, ip)
    else:
        logger.info('WRONG KEY: %s, %s', data, ip)

    return json.dumps({'success': success}), 200

def get_city_from_ip(ip_address):
    resp = requests.get('http://ip-api.com/json/%s' % ip_address).json()
    return resp['city']

def update_database(data, key, ip):
    data['ip'] = (ip, get_city_from_ip(ip))
    db[key] = {}
    db[key].update(data)
    db.sync()

def check_device(data, key, ip):
    db_data = db[key]
    if data['uid'] != db[key]['uid']:
        logger.warning('UID is different (%s). The request has been declined: %s', data['uid'], db_data)
        return False
    stored_ip, stored_city = db_data['ip']
    if ip != stored_ip:
        city = get_city_from_ip(ip)
        if city != stored_city:
            logger.warning('The ip and the city are different (%s, %s). '
                'The request has been declined: %s', ip, city, db_data)
            return False

    logger.info('The device has been authorized successfully: %s', db_data)
    return True

app.run(port=3000)
