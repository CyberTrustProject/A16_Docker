import nmap #https://pypi.org/project/python-nmap/#files
import sys
import json
#import paramiko
import subprocess
import struct
from struct import unpack
from scapy.all import *
import stomp
from stomp import ConnectionListener
import time
from datetime import datetime
import configparser
import requests

def exclude():
    config = configparser.ConfigParser(converters={'list': lambda x: [i.strip() for i in x.split(',')]})
    config.read('a16config.ini')
    excluded = config.getlist('EXCLUDED', 'EXCLUDED_IPS')
    return excluded 

def getScanSettings():
    config = configparser.ConfigParser()
    config.read('a16config.ini')
    port_range = config['SCAN_SETTINGS']['PORT_RANGE']
    timing_profile = config['SCAN_SETTINGS']['TIMING_PROFILE']
    options = config['SCAN_SETTINGS']['OPTIONS']
    return port_range,timing_profile,options

def getInterface():
    config = configparser.ConfigParser()
    config.read('a16config.ini')
    interface = config['INTERFACE_SETTINGS']['INTERFACE']
    return interface

def getAMQSettings():
    config = configparser.ConfigParser()
    config.read('a16config.ini')
    AMQ_HOST = config['AMQ_SETTINGS']['AMQ_HOST']
    AMQ_PORT = int(config['AMQ_SETTINGS']['AMQ_PORT'])
    AMQ_USER = config['AMQ_SETTINGS']['AMQ_USER']
    AMQ_PASS = config['AMQ_SETTINGS']['AMQ_PASS']
    return AMQ_HOST,AMQ_PORT,AMQ_USER,AMQ_PASS

def getCIDR():
    config = configparser.ConfigParser()
    config.read('a16config.ini')
    ip = config['DEFAULT_SETTINGS']['CIDR']
    return ip

def getPostIP():
    config = configparser.ConfigParser()
    config.read('a16config.ini')
    ip = config['POST_SETTINGS']['POST_IP']
    return ip

def registerPublish(jsonData):
    AMQ_HOST,AMQ_PORT,AMQ_USER,AMQ_PASS = getAMQSettings()
    amq_payload = jsonData
    connamq = stomp.Connection([(AMQ_HOST, AMQ_PORT)])
    connamq.connect()
    for i in range(1, 4):
        a = connamq.send(body=json.dumps(amq_payload), destination='/topic/Device.Register')
    time.sleep(1)

def cidr_to_netmask(cidr):
    network, net_bits = cidr.split('/')
    host_bits = 32 - int(net_bits)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
    return network, netmask

def genericScan(ip, scanType):
    nm = nmap.PortScanner()
    port_range, timing_profile, options = getScanSettings()
    if scanType == 'net':
        nm.scan(ip, port_range, options, timing_profile)
    elif scanType == 'single':
        nm.scan(ip, port_range, options, timing_profile)
    return nm

def getHostName(ip):
    hostdiscover = subprocess.Popen(['nmap ' + ip + ' -sn -Pn | grep "for "'],
            stdout=subprocess.PIPE, shell=True).communicate()[0]
    hostdiscover = hostdiscover.decode()
    hostdata = hostdiscover.replace('Nmap scan report for ','')
    hostsplit = hostdata.split(' ')
    if ip in hostsplit[0]:
        returnHost = '?'
    else:
        returnHost = hostsplit[0]
    return returnHost

def removeWhitespace(list):
    while True:
        try:
            list.remove('')
        except ValueError:
            break
    return list

class MyListener(ConnectionListener):
    
    def on_message(self, headers, message):
        post_func()

def query_user_devices():
    conn = stomp.Connection([('172.16.4.10', 61613)])
    conn.set_listener('', MyListener())
    conn.connect('admin', 'admin', wait=True)
    conn.subscribe(destination='/topic/Device.Register', id=1, ack='a')

def runCommand(command):
    data = []
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in p.stdout:
        decoded_line = str(line, 'utf-8')
        data.append(decoded_line)
    return data

def rest7(ip_post):
    ip = [ip_post]
    return ip

def rest8(ip, scanType):
    scan = []
    nm = genericScan(ip,scanType)
    scan_data = nm.analyse_nmap_xml_scan()
    for item in scan_data['scan']:
        scan.append(scan_data['scan'][item])
    del scan_data["scan"] 
    scan_data["scan"] = scan
    return scan_data

def rest9():
    data = runCommand(['arp','-na'])
    excluded = exclude()
    arp_result = {}
    host_interfaces = []
    for item in data:
        split = item.split(' ')
        if split[0] != '':
            ip = split[1]
            ip = ip.strip('()')
            if ip not in excluded:     
                interface_name = split[-1]
                interface_name = interface_name.strip('\n')
                macAddress = split[3]
                macAddress = macAddress.replace(":","")
                hostname = split[0]
                if interface_name == "ens4":
                    connected_to_wan = "false"
                elif interface_name == "ens3":
                    connected_to_wan = "true"
                else:
                    connected_to_wan = "false"
                if macAddress != '<incomplete>':
                    arp_result = {
                            'connected_to_wan': connected_to_wan,
                            'hostname': "host-" + macAddress,
                            'interface_name': interface_name,
                            'ip_address': ip }
                    host_interfaces.append(arp_result)
    return(host_interfaces)

def rest10():
    data = runCommand(['ip', 'route'])
    excluded = exclude()
    vlans = []
    route_result = {}
    del data[0:2]
    for item in data:
        split = item.split(' ')
        split = removeWhitespace(split)
        if '/' in split[0]:
            address,mask = split[0].split('/')
            if address not in excluded: 
                octal = address.split('.')
                octal[3] = str(int(octal[3]) + 1)
                separator = '.'
                gateway = separator.join(octal)
                name = split[2]
                netmask = mask
                route_result = {
                    'address' : address,
                    'gateway': gateway,
                    'name': name,
                    'netmask': netmask}
                vlans.append(route_result)
    return(vlans)

def rest11():
    data = runCommand(['/bin/bash','rest11.sh'])
    matrix = []
    excluded = exclude()
    for item in data:
        source_addr = ''
        destination_addr = ''
        source,destination = item.split('>')
        source_octals = source.split('.')
        destination_octals = destination.split('.')
        source_port = source_octals[4]
        destination_port = destination_octals[4][:-1]
        seperator = '.'
        source_addr = seperator.join(source_octals[:4])
        destination_addr = seperator.join(destination_octals[:4])[1:]
        if source_addr not in excluded and destination_addr not in excluded:
            
            flowMatrix = {
                "source":source_addr,
                "destination":destination_addr,
                "source_port":source_port,
                "destination_port":destination_port,
                "protocol":"tcp"
                }

            matrix.append(flowMatrix)
    return(matrix)

def rest12():
    data = runCommand(['ip', 'route'])
    routing = []
    route_result = {}
    excluded = exclude()
    del data[0:2]
    for item in data:
        split = item.split(' ')
        split = removeWhitespace(split)
        if '/' in split[0]:
            gateway,mask = cidr_to_netmask(split[0])
            octal = gateway.split('.')
            octal[3] = str(int(octal[3]) + 1)
            separator = '.'
            gateway = separator.join(octal)
            name = split[2]
            address = split[-2]
            if address not in excluded:
                route_result = {
                    'destination' : address,
                    'gateway': gateway,
                    'hostname': 'router',
                    'interface': name,
                    'mask': mask
                    }
                routing.append(route_result)
    return(routing)

def post_func(ip):
    endpoint = ["net-ip", "vuln-scan-report", "hosts-interfaces", "vlans", "flow-matrix", "routing", "initialize"]
    rest7post = rest7(ip)
    print("IP: ","\n",rest7post,"\n")
    rest8post = rest8(ip, "net")
    print("Scan: ","\n",rest8post,"\n")
    rest9post = rest9()
    print("Host: ","\n",rest9post,"\n")
    rest10post = rest10()
    print("Vlans: ","\n",rest10post,"\n")
    rest11post = rest11()
    print("Flow-Matrix: ","\n",rest11post,"\n")
    rest12post = rest12()
    print("Routing: ","\n",rest12post,"\n")
    calls = [rest7post, rest8post, rest9post, rest10post, rest11post, rest12post]
    for i in range(len(calls)):
        a13 = "http://"+str(getPostIP())+"/ag-engine-server/rest/json/v2/topology/"+endpoint[i]
        print(a13)
        data = calls[i]
        r = requests.post(url=a13, json=data)
        print("response: ", r)
        time.sleep(5)
    initialize = "http://"+str(getPostIP())+"/ag-engine-server/rest/json/v2/"+endpoint[-1]
    print(initialize)
    r = requests.get(url=initialize)
    print("response", r)

def main(ip):
    #while True:
    #    time.sleep(100)
    #    current_devices = []
    #    device_list, new_devices = get_devices(current_devices)
    #    print(device_list,'\n',new_devices)
    #    current_devices = device_list
    #    if len(new_devices) - len(device_list) == 0:
    #        print('running poster')
    #        post_func()
    #    else:
    #        print(new_devices)
    try:
        post_func(ip)
    except Exception as e:
        print(e)

