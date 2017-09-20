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

@app.route('/', methods=['GET', 'POST'])
def handle_request():
    with open('keys.txt', 'r') as f:
        keys = [i.rstrip() for i in f.readlines()]

    success = False
    data = {key: value for key, value in request.form.items()}
    ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    key = data['key']
    db = shelve.open('clients')
    try:
        if key in keys:
            if not db.get(key, None):
                data['ip'] = (ip, get_city_from_ip(ip))
                logger.info('IP : %s', ip)
                update_database(data, db, key)
                success = True
            else:
                db_data = db[key]
                success = check_device(data, db_data, ip)
        else:
            logger.info('WRONG KEY: %s, %s', data, ip)
    finally:
        db.close()

    return json.dumps({'success': success}), 200


def get_city_from_ip(ip_address):
    try:
        resp = requests.get('http://ip-api.com/json/%s' % ip_address).json()
    except requests.exceptions.ProxyError:
        return 'Unknown'
    return resp['city']


def update_database(data, db, key):
    db[key] = data
    logger.info('VALID KEY. Added to the database: %s', data)


def check_device(data, db_data, ip):
    if data['uid'] != db_data['uid']:
        logger.warning('UID is different (%s). The request has been declined: %s', data['uid'], db_data)
        return False
    stored_ip, stored_city = db_data['ip']
    if ip != stored_ip:
        city = get_city_from_ip(ip)
        if city != stored_city:
            logger.warning('The ip and the city are different (%s, %s). '
                'Data from database: %s', ip, city, db_data)
        logger.warning('IPs are different: %s-%s', ip, stored_ip)

    logger.info('The device has been authorized successfully: %s', db_data)
    return True
