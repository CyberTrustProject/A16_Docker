from flask import Flask, request, Response
import restCalls
import host_monitoring

app = Flask(__name__)

@app.route('/topology/net-ip', methods=['POST'])
def trigger():
    ip = request.json['ip']
    restCalls.main(ip)
    host_monitoring.main()
    return Response(status=200)

