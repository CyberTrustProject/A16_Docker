import time
import stomp
from stomp import ConnectionListener

class MyListener(ConnectionListener):
    def on_error(self, headers, message):
        print('received an error: ',message)

    def on_message(self, headers, message):
        print('received a message: ',message)


conn = stomp.Connection([('172.16.4.10', 61613)])
conn.set_listener('', MyListener())
conn.connect('admin', 'admin', wait=True)
conn.subscribe(destination='/topic/5002.Network.Update', id=1, ack='auto')


while True:
    time.sleep(1)
