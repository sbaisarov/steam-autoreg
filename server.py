import json
import logging
import shelve

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

# resp = requests.get('http://ip-api.com/json/%s' % ip_adress).json()
# resp['city']
app = Flask(__name__)
db = shelve.open('clients')

@app.route('/', methods=['POST'])
def handle_request():
    data = request.form
    print(data)
    return json.dumps({'success': True}), 200


app.run(port=3000)
