import socket
import sys
import time
import numpy as np
import matplotlib.pyplot as plt
import fcntl
import struct
import ipaddress
import random

TCP_IP = '10.89.0.3'
TCP_PORT = 5005
BUFFER_SIZE = 1024
MESSAGE = "Hello, World!"
print("TCP target IP:", TCP_IP)
list = []
try:
    #send data
    server_address = (TCP_IP , TCP_PORT)
    for k in range(200):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        start = time.perf_counter()
        s.connect((TCP_IP, TCP_PORT))
        for i in range(10000):
            s.send(MESSAGE.encode('utf-8'))
            data = s.recv(BUFFER_SIZE)
        s.close()
        end = time.perf_counter()
        list.append((end - start))
        sys.stdout.write("completed: %d%%\r" % (k/2) )
        sys.stdout.flush()
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