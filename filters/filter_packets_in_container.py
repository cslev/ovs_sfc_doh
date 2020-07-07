#!/usr/bin/python3
# coding: utf-8
from scapy.all import sniff , send , sendp, IP, TCP, wrpcap
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.tls.all import TLS
from scapy.layers.tls.handshake import TLSClientHello,TLS13ClientHello,TLSServerHello,TLS13ServerHello
#required for ja3 fingerprinting
import dpkt
import ja3 #TLS clienthello fingerprinting (it's a python source in the same directory)
import ja3s #TLS serverhello fingerprinting (it's a python source in the same directory)

#for argument parsing
import argparse

#for ML model
from collections import Counter
import joblib
import numpy as np

# for generating a good hash for 5-tuples
import hashlib

# for linux signal processing
import signal



## ========== PARSING ARGUMENTS ==========
parser = argparse.ArgumentParser(description="Python-based DNS filter!")

parser.add_argument('-f', '--filter-dns', action="store_true", dest="filter_dns" , help="Enable pure DNS based filtering (Default: False)")
parser.set_defaults(filter_dns=False)

parser.add_argument('-d', '--domain', action="store", default="index.hu", type=str, dest="domain_to_filter" , help="Specify the domain to filter for with DNS (Default: index.hu)! Use only with -f/--filter-dns option!")

parser.add_argument('-g', '--filter-doh', action="store_true", dest="filter_doh" , help="Enable DoH-based filtering - This will drop all packets that looks like a DoH query (Default: False)")
parser.set_defaults(filter_doh=False)
parser.add_argument('-m', '--ml-model', action="store", dest="model", type=str, default="../ml_models/modelv3.pkl", help="Specify the ML model's location! (Default: ../ml_models/modelv3.pkl <- mind the relative path!)")
parser.add_argument('-t', '--doh-threshold', action="store", dest="threshold", type=int, default=2, help="Specify the threshold for a service to be identified as DoH! (Default: 2) Refer to source code coment for more details!")
parser.add_argument('-l', '--web-threshold', action="store", dest="threshold_https", type=int, default=-10, help="Specify the negative threshold for a service identified as Web to reset its counter! (Default: -10) Refer to source code coment for more details!")
parser.add_argument('-v', '--verbose', action="store_true", dest="verbose" , help="Verbose mode (Default: False)")
parser.set_defaults(verbose=False)

"""
Threshold for DoH:
It is not a simple counter/indicator to identify a service as DoH is classified as DoH 'threshold' times.
When a tuple/flow has been once seen, it is saved with a counter value of 0. Once the packets belonging to 
this flow is identified as DoH, the counter is increased. If another packet from the same flow is identified then 
as Web, then the counter will be decreased.
Accordingly, the threshold value here means how high the counter should be (obviously a positive integer) in order to (finally)
decide whether a service is DoH. 
So, even if a packet of a flow has been identified as DoH 100 times, if other packets from the same flow were also identified as HTTP 101 times
then having a threshold of 2 results in that the flow will not blocked (yet)
""" 

results = parser.parse_args()

FILTER_DNS=results.filter_dns
DOMAIN_TO_FILTER=results.domain_to_filter
FILTER_DOH=results.filter_doh
MODEL=results.model
VERBOSE=results.verbose
THRESHOLD=results.threshold
WEB_THRESHOLD=results.threshold_https

print("Configuration:")
if(not FILTER_DNS and not FILTER_DOH):
  print("BLIND FORWARDING MODE")
else:
  print("The following domain will be blocked via pure DNS: {}".format(DOMAIN_TO_FILTER))

if(not FILTER_DOH):
  print("DNS-over-HTTPS is allowed")
else:
  print("DNS-over-HTTPS needs to be blocked")
  rf3 = joblib.load(MODEL)
  rf3.verbose=0
  print("ML MODEL has been loaded")


# data structure for storing packet data
# ~ packet_data={
          # ~ "src_ip":"",
          # ~ "dst_ip":"",
          # ~ "src_port":0,
          # ~ "clientHello":"",  #JA3  fingerprint
          # ~ "serverHello":"",  #JA3S fingerprint
          # ~ "class":0         #0, if DoH +=1, if Web -=1 --> blocked if reaches 2
          # ~ "doh":0
          # ~ "web":0
        # ~ }
# dictionary to store packet_datas, will be keyed be a hash of the 5-tuple
flows=dict()

# server JA3S to be blocked (fingeprint:IP)
server_fingerprints=dict()


################ FUNCTIONS ######################


def receiveSignal(signalNumber, frame):
  """
  This function is called when a Linux signal (e.g., Ctrl+C) is caught.
  """
  if(signalNumber == 2): #Ctrl+C signal caught
    print("Signal received:{}".format(signalNumber))
    print("Flow data...")
    
    for i in flows:
      print("----------------------------")
      print("hash:          {}".format(i))
      print("source:        {}".format(flows[i]["src_ip"]))
      print("destination:   {}".format(flows[i]["dst_ip"]))
      print("source port:   {}".format(flows[i]["src_port"]))
      print("ja3 (client):  {}".format(flows[i]["clientHello"]))
      print("ja3s (server): {}".format(flows[i]["serverHello"]))
      print("(last) class:  {}".format(flows[i]["class"]))
    
    print("=============================")    
    print("Blocked servers' fingerprint data...")
    for i in server_fingerprints:
      print("----------------------------")
      print("server (IP):   {}".format(server_fingerprints[i]))
      print("ja3s:          {}".format(i))
      
    print("Exiting...")
    exit(-1)


#simplest and one of the fastest hash function according to a test here
#https://www.peterbe.com/plog/best-hashing-function-in-python
#so, we will use this for now
def h11(w):
    return hashlib.md5((w.encode('utf-8'))).hexdigest()[:9]
    

##  ============ PURE DNS FILTERING ============
def filter_dns_packets(packet):
  if packet.qdcount > 0 and isinstance(packet.qd, DNSQR):
    #print("DNS query")
    name = packet[DNSQR].qname
    #print(name)
    if(DOMAIN_TO_FILTER in str(name)):
      # DNS queries looking for DOMAIN_TO_FILTER will be dropped
      print("Gotcha {}  - DROP".format(DOMAIN_TO_FILTER))
    else:
      # FORWARD every other DNS queries
      sendp(packet, iface="eth0", verbose=0)
      print("FORWARDING DNS query ({})...".format(name))
## ------- PURE DNS FILTERING END ------


## ======== MAKING JA3(S) FINGERPRINING ==========
def fingerprint_tls(tmp_pcap_file, client_hello):
  """Fingerprint TLS hello packets 
  :param tmp_pcap_file: pcap file storing the client/server hello packet
  :type tmp_pcap_file: string: a path to the pcap file
  :param client_hellp: indicating if client hello should be processed
  :type ja3: bool: True:client hello, False: server hello
  """
  # data ja3 library can provide
  # "source_ip"
  # "destination_ip"
  # "source_port"
  # "destination_port"
  # "ja3": ja3
  # "ja3_digest"
  # "timestamp"
  
  output = None
  error_happened = False
  with open(tmp_pcap_file, 'rb') as fp:
    capture = dpkt.pcap.Reader(fp)
    if(client_hello): #CLIENTHELLO
      try:
        output = ja3.process_pcap(capture, any_port=False) 
        src, dst, port, ja3_digest = output[0]['source_ip'], output[0]['destination_ip'], output[0]['source_port'], output[0]['ja3_digest']
      except IndexError:
        print("JA3 fingerprinting failed...CONTINUE")
        error_happened = True
    else: #SERVERHELLO
      try:
        output = ja3s.process_pcap(capture, any_port=False) 
        src, dst, port, ja3_digest = output[0]['source_ip'], output[0]['destination_ip'], output[0]['destination_port'], output[0]['ja3_digest']
      except IndexError:
        print("JA3 fingerprinting failed...CONTINUE")
        error_happened = True
      
  # print("Closing pcap...")
  fp.close()
  os.remove(tmp_pcap_file)
  
  if(not error_happened):
    return src,dst,port,ja3_digest
  else:
    return None,None,None,None
## ------ MAKING JA3 FINGERPRINTING END -------



## ============  DNS-over-HTTPS filtering ===========
def filter_doh_packets(packet):

  #we will convert Scapy packet to dpkt packet
  #easiest way to write it into a pcap, and read it via dpkt modules
  # ~ data=packet_data
  # --------- CLIENTHELLO -----------
  if(packet.haslayer(TLSClientHello)):
    tmp_pcap_file="tmp_tls_clienthello.pcap"
    if(VERBOSE):
      print("TLSClientHello")
    #write packet to pcap file
    wrpcap(tmp_pcap_file, packet)
    # get ja3 fingerprints and other metadata
    src,dst,src_port,ja3_digest=fingerprint_tls(tmp_pcap_file, True)
    #check return values
    if(src is None):
      #error happened during fingerprinting
      return
      
    if(VERBOSE):
      print("{}:{} -> {}:443, ja3 TLS fingerprint: {} ".format(src, src_port, dst, ja3_digest))
    
    #create hash for the 3-tuple for identification (port 443 and protocol is just overhead)
    three_tuple=str(src) + str(dst) #+ str(src_port)      
    h=h11(three_tuple)
    #create packet data
    if(h not in flows):
      flows[h]=dict()
      flows[h]["src_ip"]=src
      flows[h]["dst_ip"]=dst
      flows[h]["src_port"]=src_port
      flows[h]["clientHello"]=ja3_digest
      flows[h]["serverHello"]=""
      flows[h]["class"]=0
      flows[h]["doh"]=0
      flows[h]["web"]=0
    
    # data["src_ip"]=src
    # data["dst_ip"]=dst
    # data["src_port"]=src_port
    # data["clientHello"]=ja3_digest
    # data["serverHello"]=""  #JA3S fingerprint is empty for now
    # data["class"]=""        #Class is empty for now
    
    # print(type(data["src_port"]))
    

    #add packet data to the flows dictionary
    # flows[h]=data
    
    #send packet forward and return (ML MODEL anyway has nothing to do with TLS handshakes
    sendp(packet, iface="eth0",verbose=0)
    return
  
  # -------- SERVERHELLO ----------
  elif(packet.haslayer(TLSServerHello)):
    tmp_pcap_file="tmp_tls_serverhello.pcap"
    if(VERBOSE):
      print("TLSServerHello")
      
    # write packet to pcap file
    wrpcap(tmp_pcap_file, packet)
    # get ja3s fingerprints and other metadata
    src,dst,dst_port,ja3_digest=fingerprint_tls(tmp_pcap_file, False)
    #check return values
    if(src is None):
      #error happened during fingerprinting
      return
      
    #It is a serverhello, so clienthello should already add this communication to the flows[] dictionary
    #Let's create the key for indexint
    #create hash for the 3-tuple for identification (port 443 and protocol is just overhead)
    #have to change source and destination, and source port to destination port
    three_tuple=str(dst) + str(src) # + str(dst_port)  
    
    h=h11(three_tuple)

    if(h not in flows): #double-check whether the tuple assemblance was OK (everything is mix-and-matched propery)
      #this can happen if for some reason, we only catch a serverhello, but the clienthello was missed
      sendp(packet, iface="eth0",verbose=0)
      return
      
    if(VERBOSE):
      print("{} -> {}:{}, ja3s TLS fingerprint: {} (count:{})".format(src, dst, dst_port, ja3_digest, flows[h]['class']))
    if(ja3_digest in server_fingerprints):
      print("Server {} is DoH server with ja3s {}, dropping ServerHello message...".format(src,ja3_digest))
      return
      
    #update serverhello fingerprint
    flows[h]["serverHello"]=ja3_digest
    
    #send packet forward and return (ML MODEL anyway has nothing to do with TLS handshakes
    sendp(packet, iface="eth0",verbose=0)
    return
  
  elif(packet.haslayer(TLS13ClientHello)):
    if(VERBOSE):
      print("TLS13ClientHello")
    pass
  elif(packet.haslayer(TLS13ServerHello)):
    if(VERBOSE):
      print("TLS13ServerHello")
    pass
  else:
    # Our MODEL only checks outgoing packets (i.e., request packets), so let's filter them
    # When destination port is not 443, or source_port is 443, then it is a response packet
    if(packet[0][2].sport == 443):
      sendp(packet, iface="eth0",verbose=0)
      return
    
    def make_pred(packet):
        # custom_action.number+=1
        # print(f"Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}")
        #key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
        # packet_counts.update([key])

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
        
        three_tuple=str(packet[0][1].src) + \
                str(packet[0][1].dst) # + \
                #str(packet[0][2].sport)
        h=h11(three_tuple)
        
        #Stale TLS packets (e.g., resebt Application Data from previous 
        #connection) can cause error here if the corresponding handshakes
        #were not caught! Such packets will be dropped here
        if(h not in flows):
          return
        #get corresponding serverhello fingeprint
        ja3s=flows[h]["serverHello"]

        if(prediction==1) :
          ans = 'DoH'
          # print("packet looks like DoH...DROP")
          print("DoH service IP? : {}".format(packet[0][1].dst))
          
          # ~ flows[h]['class']="DoH"
          # ~ flows[h]['class']+=1
          # ~ if(flows[h]['class'] >= THRESHOLD):
            # ~ print("ja3s {} from server {} has been added to blocklist".format(ja3s,packet[0][1].dst))
            # ~ server_fingerprints[ja3s]=packet[0][1].dst
            
          flows[h]['doh']+=1
          if(flows[h]['doh'] >= THRESHOLD):
            print("ja3s {} from server {} has been added to blocklist".format(ja3s,packet[0][1].dst))
            server_fingerprints[ja3s]=packet[0][1].dst
            flows[h]['doh'] = 0
          
          
          
        else :
          ans = 'Http2'
          # ~ flows[h]['class']="Http2"
          # ~ flows[h]['class']-=1
          # ~ if((flows[h]['class'] < WEB_THRESHOLD) and (ja3s in server_fingerprints)): #if reduces back below the limit, we remove fingerprint from blocklist if it has ever added
            # ~ print("ja3s {} from server {} has been removed from blocklist".format(ja3s,packet[0][1].dst))
            # ~ del server_fingerprints[ja3s]
            # ~ flows[h]['class'] = 0
          flows[h]['web']+=1  
          if((flows[h]['web'] <= WEB_THRESHOLD) and (ja3s in server_fingerprints)):
            print("ja3s {} from server {} has been removed from blocklist".format(ja3s,packet[0][1].dst))
            del server_fingerprints[ja3s]
            flows[h]['web'] = 0
            
          #reset counter if needed
          # ~ if(flows[h]['class'] < WEB_THRESHOLD):
            # ~ flows[h]['class'] = 0
          print("HTTP service IP? : {}".format(packet[0][1].dst))
          sendp(packet, iface="eth0",verbose=0)

        # ~ if(VERBOSE):
          # ~ print("The packet was : "+ ans)
        # print(X_train)
        # diff = t1-t0
        # diff = round(diff,5)
        #print("Prediction time is "+ str(diff) +"sec" )


        ### updating values for next cycle
        filter_doh_packets.prev_time = time
        filter_doh_packets.prev_lag = time_lag_curr
        filter_doh_packets.prev_number = filter_doh_packets.number
        filter_doh_packets.prev_len = length

    # print("Making prediction for packet:")
    # print(packet.summary())
    return make_pred(packet)

filter_doh_packets.prev_time = 0
filter_doh_packets.prev_len = 0
filter_doh_packets.prev_lag = 0
filter_doh_packets.number = 0
filter_doh_packets.prev_number= 0
## ----- DNS-over-HTTPS filtering END ----------------




def filter_packets(packet):
  #Scapy cannot distinguish between incoming and outgoing packets, so
  #to avoid infinite loop, let's change outgoing packet's MAC
  new_mac="00:11:22:33:44:55"

  if IP in packet:
    
    #packets coming from the user
    if(packet[0][1].dst != "10.10.10.101" and packet[0][0].src != new_mac):
      #setting the source MAC to a pseudo-random one
      packet[0][0].src=new_mac

      ### ------- HERE COMES ANY FILTERING --------- ###
      ##------- NO FILTER ---------
      if(not FILTER_DNS and not FILTER_DOH):
        # FORWARD everything else
        sendp(packet, iface="eth0", verbose=0)
        if (VERBOSE):
          print("FORWARDING without restriction")
      ## -------- FILTERING -------
      else:
        ##  ============ PURE DNS FILTERING ============
        if(packet.haslayer(DNS) and FILTER_DNS):
          filter_dns_packets(packet)
        ## ------- PURE DNS FILTERING END ------

        ## ============  DNS-over-HTTPS filtering ===========
        elif(packet.haslayer(TLS) and FILTER_DOH):
          filter_doh_packets(packet)
        ## ----- DNS-over-HTTPS filtering END ----------------
        else:
          sendp(packet, iface="eth0", verbose=0)
          # print("FORWARDING non-filtered packets")
      ####============== FILTERING ENDS ============####


    elif(packet[0][1].dst == "10.10.10.101"):
      # This host was the destination
      # print("I was the destination")
      pass
    elif(packet[0][1].src == "10.10.10.101"):
      # Reply sent
      # print("Reply sent")
      pass
    else:
      #this is actually the same packet but outgoing...scapy sniffer
      # print("Packet sent out")
      pass


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


#we cannot filter on anything, because then packets missing the filter will not
#be forwarded by default
sniff(iface="eth0", prn=filter_packets)
