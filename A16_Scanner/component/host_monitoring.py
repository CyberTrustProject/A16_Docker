import nmap #https://pypi.org/project/python-nmap/#files
import sys
import json
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
import os

def exclude():
    config = configparser.ConfigParser(converters={'list': lambda x: [i.strip() for i in x.split(',')]})
    config.read('a16config.ini')
    excluded = config.getlist('EXCLUDED', 'EXCLUDED_IPS')
    return excluded

def getpfSenseCreds():
    config = configparser.ConfigParser()
    config.read('a16config.ini')
    ip = config['SSH_SETTINGS']['PFSENSE_SSH_IP']
    username = config['SSH_SETTINGS']['SSH_USERNAME']
    password = config['SSH_SETTINGS']['SSH_PASSWORD']
    return ip,username,password

def getScanSettings():
    config = configparser.ConfigParser()
    config.read('a16config.ini')
    port_range = config['SCAN_SETTINGS']['PORT_RANGE']
    return port_range

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

def getStandardIP():
    config = configparser.ConfigParser()
    config.read('a16config.ini')
    ip = config['DEFAULT_SETTINGS']['CIDR']
    return ip

def getNetworkUpdateAddress():
    config = configparser.ConfigParser()
    config.read('a16config.ini')
    topic = config['NETWORK_UPDATE']['BUS_TOPIC']
    return topic

def cidr_to_netmask(cidr):
    network, net_bits = cidr.split('/')
    host_bits = 32 - int(net_bits)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
    return network, netmask

def genericScan(ip, scanType):
    timingProfile = '--min-rate 200, --max-rtt-timeout 100ms '
    options = '--exclude 192.168.0.1,192.168.0.2,192.168.0.3,192.168.0.4,192.168.0.5,192.168.0.6,192.168.0.7 -sC -sV --script vulners'
    nm = nmap.PortScanner()
    port_range = getScanSettings()
    if scanType == 'net':
        nm.scan(ip,  port_range, options)
    elif scanType == 'single':
        nm.scan(ip, port_range, options)
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


def alert_return(alerts):
    AMQ_HOST = '172.16.4.10'
    AMQ_PORT = 61613
    AMQ_USER = 'admin'
    AMQ_PASS = 'admin'
    TOPIC = getNetworkUpdateAddress()
    print(TOPIC)
    amq_payload = alerts
    connamq = stomp.Connection([(AMQ_HOST, AMQ_PORT)])
    connamq.connect()
    for i in range(1):
        a = connamq.send(body=json.dumps(amq_payload), destination=TOPIC)
    time.sleep(0.1)
    #connamq.disconnect()

def runCommand(command):
    data = []
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in p.stdout:
        decoded_line = str(line, 'utf-8')
        data.append(decoded_line)
    return data

def host_check():
    data = runCommand(['arp','-na'])
    arp_result = {}
    host_interfaces = []
    host_list = []
    for item in data:
        split = item.split(' ')
        if split[0] != '':
            ip = split[1]
            ip = ip.strip('()')
            interface_name = split[-1]
            interface_name = interface_name.strip('\n')
            macAddress = split[3]
            macAddress = macAddress.replace(":","")
            hostname = split[0]
            if interface_name == "ens4":
                connected_to_wan = "false"
            elif interface_name == "ens3":
                connected_to_wan = "true"
            if macAddress != '<incomplete>':
                host = "host-" + macAddress
                host_list.append(host)
    return(host_list)


def get_ip(query_host):
    data = runCommand(['arp','-na'])
    arp_result = {}
    host_interfaces = []
    for item in data:
        split = item.split(' ')
        if split[0] != '':
            ip = split[1]
            ip = ip.strip('()')
            interface_name = split[-1]
            interface_name = interface_name.strip('\n')
            macAddress = split[3]
            macAddress = macAddress.replace(":","")
            hostname = split[0]
            if interface_name == "ens4":
                connected_to_wan = "false"
            elif interface_name == "ens3":
                connected_to_wan = "true"
            
            if ("host-"+macAddress) == query_host:
                    return(ip)
                    break

def host_compare():
    excluded = exclude()
    print('\n')
    previous_hosts = [] 
    #previous_hosts = host_check()
    #i = 1 
    connected_devices_post = []
    disconnected_devices_post = []
    for x in range(2):
        
        new_hosts = host_check()
        print("previous_hosts: ","\n",previous_hosts)

        #new_hosts.append('host-fa163e82123' + str(i)) # Testing +1 new client
        print("new_hosts: ","\n",new_hosts)

        for item in new_hosts:
            if item in previous_hosts:
                ()
            elif item not in previous_hosts:
                previous_hosts.append(item)
                ip = get_ip(item) 
                mac_start = item[5:]
                mac_split = iter(mac_start)
                mac = ':'.join(a+b for a,b in zip(mac_split, mac_split))
                message = {
                        'status': 'connected',
                        'hostname': item,
                        'ip_address': ip,
                        'mac': mac
                        }
       
                print(message)
                if message['ip_address'] in excluded:
                    print("Excluded as item is a SOHO Component")
                else:
                    if message['ip_address'].startswith('172') == False:
                        connected_devices_post.append(message)


        for item in previous_hosts:
            if item not in new_hosts:
                previous_hosts.remove(item)
                mac_start = item[5:]
                mac_split = iter(mac_start)
                mac = ':'.join(a+b for a,b in zip(mac_split, mac_split))
                message = {
                        'status': 'disconnected',
                        'hostname': item,
                        'ip_address': ip,
                        'mac': mac
                        }
                
                print(message)
                if message['ip_address'] in excluded:
                    print("Excluded as item is a SOHO Component")
                elif message['ip_address'].startswith('192') == False:
                    print("Excluded as item is not a LAN Device")
                else:
                    if message['ip_address'].startswith('172') == False:
                        disconnected_devices_post.append(message)
        
        alert_return(connected_devices_post)
        alert_return(disconnected_devices_post)
        time.sleep(2)
        #i += 1
        
def main():
    host_compare()
