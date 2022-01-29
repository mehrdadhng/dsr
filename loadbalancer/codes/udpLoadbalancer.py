import socket
from scapy.all import *
import csv

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the port
server_address = ('10.89.0.3', 3000)
print ('starting up on {} port {}'.format(server_address[0], server_address[1]))
sock.bind(server_address)
ports = []
to_hash = []
number_of_servers = 32;
file = open('destination_samples/32_destinations.csv')
csvreader = csv.reader(file)
rows = []
for row in csvreader:
	rows.append(row)
print(rows[0])
servers = []
for i in range(512):
	servers.append(rows[i%len(rows)])

while True:
    print ('\nwaiting to receive message')
    data, address = sock.recvfrom(4096)
    address = list(address) 
    print ('received {} bytes from {}'.format(len(data), address))
    #print (data)
    #address[0] = address[0][:-1]
    if(address[0][-1] == "2"):
    	to_hash.append(address[0])
    	to_hash.append(address[1])
    	to_hash.append(3000)
    	to_hash = tuple(to_hash)
    	hash_value = hash(to_hash)
    	index = hash_value%number_of_servers
		server = servers[index]
		send(IP(dst=server[0],src="10.89.0.3")/IP(dst="10.89.0.3",src=address[0])/UDP(dport=3000)/data)
    	# address[0] = address[0][0:-1]+"2"
    	# ports.append(address[1])
    	# address[1] = 3000
    	# sent = sock.sendto(data , tuple(address))
    	# print ('sent {} bytes back to {}'.format(sent, address));
