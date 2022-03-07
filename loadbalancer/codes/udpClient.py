import socket
import sys
import time
import numpy as np
import matplotlib.pyplot as plt
import fcntl
import struct
import ipaddress
import random

def clear_arp(ip, ifname=''):
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    
            ip_bytes = int(ipaddress.IPv4Address(ip)).to_bytes(4, byteorder='big')
            fcntl.ioctl(sock.fileno(),0x8953,struct.pack('hh48s16s', socket.AF_INET, 0, ip_bytes, ifname[:15].encode()))
        except OSError as e:
            break
        finally:
            sock.close()
            struct.pack('hh48s16s', socket.AF_INET, 0, ip_bytes, ifname[:15].encode())

MESSAGE = "MESSAGE CONTENT"
UDP_IP = "10.89.0.3"
UDP_PORT = 3000

print("UDP target IP:", UDP_IP)
#print("message:", MESSAGE)

list = []
# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print("200 iterations, each iteration: 10000 packets...")
try:
    # Send data
    #print ('sending {}'.format(MESSAGE))
    server_address = (UDP_IP , UDP_PORT)
    for k in range(200):
        start = time.perf_counter()
        for i in range(100):
            sent = sock.sendto(MESSAGE.encode(), server_address)
            data, server = sock.recvfrom(4096)
            #clear_arp('10.89.0.3')
        end = time.perf_counter()
        list.append((end - start))
        sys.stdout.write("completed: %d%%\r" % (k/2) )
        sys.stdout.flush()
        #print('completed: [%d%%]\r'%(k/2), end="")

finally:
    mean = np.mean(list)
    std = np.std(list)
    fig, ax = plt.subplots()
    textstr = '\n'.join((r'$\mu=%.5f$' % (mean, ), r'$\sigma=%.5f$' %(std, )))
    ax.hist(list , bins = 25, color = "black")
    props = dict(boxstyle='round', facecolor='wheat', alpha=0.5)
    ax.text(0.95, 0.95, textstr, transform=ax.transAxes, fontsize=14, verticalalignment='top' , horizontalalignment='right', bbox=props)
    plt.axvline(mean, color='red', linestyle='dashed', linewidth=1)
    plt.title("histo(2hop)")
    #plt.text(0 , 25 , "mean : " + str(mean) + "\n" + "std : " + str(std))
    plt.savefig("histo_2hop.jpg")
    plt.show()
    sys.stdout.flush()
    sys.stdout.flush()
    sys.stdout.write("closing socket\n")
    sock.close()
