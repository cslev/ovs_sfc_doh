#!/usr/bin/python3
# coding: utf-8

from scapy.all import sniff , send , sendp, IP, rdpcap #the latter for pcap reading
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.tls.all import TLS
import argparse

#for ML model
from collections import Counter
import joblib
import numpy as np 

# for generating a good hash for 5-tuples
import hashlib

# for running ovs-ofctl command
import os

# for timestamping
import time
import datetime

# for linux signal processing
import signal

def getDateFormat(timestamp):
  '''
  This simple function converts traditional UNIX timestamp to YMD_HMS format
  timestamp int - unix timestamp to be converted
  return String - the YMD_HMS format as a string
  '''
  return datetime.datetime.\
          fromtimestamp(float(timestamp)).strftime('%Y%m%d_%H%M%S')


parser = argparse.ArgumentParser(description="Python-based DoH analyzer " + \
          "for PCAP files. It reads the PCAP file, uses a machine " +\ 
          "model to decide whether an HTTPS packet is DoH or Web")
parser.add_argument('-p', 
                    '--pcap-file', 
                    action="store", 
                    required=True,                    
                    type=String, 
                    dest="pcap", 
                    help="Specify the pcap file to read!")
parser.add_argument('-m', 
                    '--ml-model', 
                    action="store", 
                    dest="model", 
                    default="../ml_models/modelv3.pkl", 
                    help="Specify the ML model's location! (Default: " +\ 
                    "../ml_models/modelv3.pkl <- mind the relative path!)")
                    
args = parser.parse_args()
PCAP = args.pcap
MODEL=results.model



print("Loading model {}".format(MODEL))
rf3 = joblib.load(MODEL)
rf3.verbose=0
print("ML model has been loaded")

# initializing vars
filter_doh_packets.prev_time = 0
filter_doh_packets.prev_len = 0 
filter_doh_packets.prev_lag = 0
filter_doh_packets.number = 0
filter_doh_packets.prev_number= 0  


#get current timestamp and convert it
ts = time.time()
timestamp = getDateFormat(str(ts))

# Open log files for blacklist five-tuples
logfile = open("doh_log_"+logfile_suffix+str(timestamp), "w")


def make_pred(packet):
  
  
  three_tuple = str(packet[0][1].src) + \
                str(packet[0][1].dst) + \
                str(packet[0][2].sport)
              

    
  ### calculating packet parameters
  time = packet.time 
  time_lag_curr = time - filter_doh_packets.prev_time
  time_lag_prev = filter_doh_packets.prev_lag
  length = len(packet)
  prev_length = filter_doh_packets.prev_len
  packet_difference = filter_doh_packets.number - filter_doh_packets.prev_number

  ### prediction
  #t0=time
  X_train =[length , prev_length , time_lag_curr, time_lag_prev, packet_difference]
  X_train = np.array(X_train)
  X_train = X_train.reshape(1,-1)
  prediction = rf3.predict(X_train)
  #t1 = time

  #initialize data structure
  # ~ ips[packet[0][1].dst]=ip_class
  

    
  # ~ h=h11(three_tuple)
  #### ----------- DoH -------------
  if(prediction==1) :
    ans = 'DoH'
    # print("packet looks like DoH...DROP")
    # print("DoH service IP? : {}".format(packet[0][1].dst))
    print("DoH (predicted):{}".format(three_tuple)
    logfile.write(str("DoH (predicted):{}\n".format(three_tuple))

  #### ----------- HTTP2 -----------
  else :
    ans = 'Web'
    print("Web (predicted):{}".format(three_tuple)
    logfile.write(str("Web (predicted):{}\n".format(three_tuple))

   
  logfile.flush()
  
  ### updating values for next cycle
  filter_doh_packets.prev_time = time
  filter_doh_packets.prev_lag = time_lag_curr
  filter_doh_packets.prev_number = filter_doh_packets.number 
  filter_doh_packets.prev_len = length
    
    
    
# signing up for all UNIX signals
signal.signal(signal.SIGHUP, receiveSignal)
signal.signal(signal.SIGINT, receiveSignal)
signal.signal(signal.SIGQUIT, receiveSignal)
signal.signal(signal.SIGILL, receiveSignal)
signal.signal(signal.SIGTRAP, receiveSignal)
signal.signal(signal.SIGABRT, receiveSignal)
signal.signal(signal.SIGBUS, receiveSignal)
signal.signal(signal.SIGFPE, receiveSignal)
#signal.signal(signal.SIGKILL, receiveSignal) # has to be able to be killed :)
signal.signal(signal.SIGUSR1, receiveSignal)
signal.signal(signal.SIGSEGV, receiveSignal)
signal.signal(signal.SIGUSR2, receiveSignal)
signal.signal(signal.SIGPIPE, receiveSignal)
signal.signal(signal.SIGALRM, receiveSignal)
signal.signal(signal.SIGTERM, receiveSignal)


#let's read the pcap file
packets = rdpcap(PCAP)

#process packets
for packet in packets:
  #HTTPS packet going for a service behind 443?  
  if(packet[0][2].dport == 443):
    #TLS packet?
    if(packet.haslayer(TLS))
      make_pref(packet)
  
