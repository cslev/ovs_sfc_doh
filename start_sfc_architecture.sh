#!/bin/bash

ML_MODEL="model2_rf3.pkl"
{
#COLORIZING
none='\033[0m'
bold='\033[01m'
disable='\033[02m'
underline='\033[04m'
reverse='\033[07m'
strikethrough='\033[09m'
invisible='\033[08m'

black='\033[30m'
red='\033[31m'
green='\033[32m'
orange='\033[33m'
blue='\033[34m'
purple='\033[35m'
cyan='\033[36m'
lightgrey='\033[37m'
darkgrey='\033[90m'
lightred='\033[91m'
lightgreen='\033[92m'
yellow='\033[93m'
lightblue='\033[94m'
pink='\033[95m'
lightcyan='\033[96m'
}

function check_retval ()
{
  retval=$1
  if [ $retval -ne 0 ]
  then
    echo -e "${bold}${red}[FAIL]${none}"
    #echo -e "Check the commands you are using for more details!"
    #echo -e "EXITING${none}"
    exit -1
  else
    echo -e "\t${bold}${green}[DONE]${none}"
  fi
}


function show_help
{

  echo -e "${green}Example: sudo ./start_sfc_architecture.sh -o <INTERNET_FACING_ETH>${none}"
  echo -e "\t\t-o <INTERNET_FACING_ETH>: The device name on your host/ in your VM used for accessing the INTERNET"
  echo -e "\t\t-c: enable container based filtering"
  exit
}

PUB_INTF=""
CONTAINER_BASED=0
while getopts "h?o:c" opt
do
  case "$opt" in
  h|\?)
    show_help
    ;;
  o)
    PUB_INTF=$OPTARG
    ;;
  o)
    CONTAINER_BASED=1
    ;;
  *)
    show_help
   ;;
  esac
done


if [[ "$PUB_INTF" == "" ]]
then
	echo -e "${ref}${bold}INTERNET_FACING_ETH is not defined\n${none}"
	show_help
fi

echo -e "${blue}Checking interface ${PUB_INTF}..."
sudo ifconfig |grep $PUB_INTF 1> /dev/null
retval=$?
check_retval $retval



CONTAINER1="user"
CONTAINER1_IP="10.10.10.100"

CONTAINER2="filter"
CONTAINER2_IP="10.10.10.101"

sudo docker stop $CONTAINER1 2> /dev/null
sudo docker stop $CONTAINER2 2> /dev/null


sudo docker rm $CONTAINER1 2> /dev/null
sudo docker rm $CONTAINER2 2> /dev/null

GATEWAY=ovsbr-pub
VETH_GATEWAY=veth_public
#GATEWAY_IP="192.168.1.1/16"
GATEWAY_IP="10.10.10.1"

PRIVATE=ovsbr-int
VETH_PRIVATE=veth_private

#cleanup
sudo ip link del $VETH_PRIVATE > /dev/null 2>&1

# TOPOLOGY
#+---------+        +------------------+
#| user    |        | filter           |
#+---------+        +------------------+
#     |                  |            
#10.10.10.100/24   10.10.10.101/24   
#     |                  |          
#+----------------------------------+                             +------------------------------+
#|                            ______|                             |____                          |
#| OVSBR-INT                 |veth0 ------------------------------veth1|                OVSBR-PUB---------- INTERNET
#|                            ------|                             |-----          10.10.10.1/24  |
#+----------------------------------+                             +------------------------------+


echo -e "${blue}Starting OVS bridges...${none}"
sudo ./start_ovs.sh -n $PRIVATE
sudo ovs-vsctl add-br $GATEWAY
echo -e "${green}${done}[DONE]${none}"


echo -en "${blue}Creating veth pair to connect the bridges...${none}"
sudo ip link del $VETH_GATEWAY 2> /dev/null
sudo ip link add $VETH_GATEWAY type veth peer name $VETH_PRIVATE
retval=$?
check_retval $retval

echo -en "${blue}Connecting bridges...${none}"
sudo ovs-vsctl add-port $GATEWAY $VETH_GATEWAY
sudo ovs-vsctl add-port $PRIVATE $VETH_PRIVATE
retval=$?
check_retval $retval


echo -en "${blue}Setting up IP address for Internet access...${none}"
sudo ifconfig $GATEWAY $GATEWAY_IP/24 up
sudo ifconfig $VETH_PRIVATE up
#sudo ifconfig $VETH_PRIVATE ${VETH_PRIVATE_IP}/24 up
sudo ifconfig $VETH_GATEWAY up
retval=$?
check_retval $retval


echo -en "${blue}Creating iptables rules for NAT between ${PUB_INTF} and ${GATEWAY} ${none}"
sudo echo 1 > /proc/sys/net/ipv4/ip_forward
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t nat -A POSTROUTING -o $PUB_INTF -j MASQUERADE
sudo iptables -A FORWARD -i $GATEWAY -j ACCEPT
sudo iptables -A FORWARD -i $PUB_INTF -o $GATEWAY -m state --state RELATED,ESTABLISHED -j ACCEPT
echo -e "${green}${done}[DONE]${none}"




echo -e "${blue}Starting two containers (${CONTAINER1},${CONTAINER2}) in privileged mode...${none}"
echo -en "\tStarting container ${CONTAINER1}...${none}"
sudo docker run -dit --name=$CONTAINER1 --net=none -e DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix -v $HOME/.Xauthority:/root/.Xauthority --hostname $(hostname) cslev/docker_firefox:selenium "xterm -fn 10x20"
retval=$?
check_retval $retval

echo -en "${blue}Adding some time to ${CONTAINER1}"
for i in {1..3}
do
  echo -en "."
  sleep 1s
done
echo -en "${none}"

echo -en "${blue}Testing whether ${CONTAINER1} is up and running"
sudo docker ps -a |grep $CONTAINER1 > /dev/null 2>&1
retval=$?
check_retval $retval

echo -en "\tStarting container ${CONTAINER2}...${none}"
sudo docker run -dit --rm --privileged --name=$CONTAINER2 --net=none cslev/debian_networking bash
retval=$?
check_retval $retval
echo -e "Use sudo docker ps to see their details and use sudo docker attach to get into them!\n"

echo -en "${blue}Connecting ${CONTAINER1} to OVS (${PRIVATE})...${none}"
sudo chmod +x ovs-docker
sudo ./ovs-docker add-port $PRIVATE eth0 $CONTAINER1 --ipaddress=$CONTAINER1_IP/24 --gateway=$GATEWAY_IP
retval=$?
check_retval $retval

echo -en "${blue}Connecting port1 of ${CONTAINER2} to OVS (${PRIVATE})...${none}"
sudo ./ovs-docker add-port $PRIVATE eth0 $CONTAINER2 --ipaddress=$CONTAINER2_IP/24 --gateway=$GATEWAY_IP
retval=$?
check_retval $retval

#echo -en "${blue}Connecting port2 of ${CONTAINER2} to OVS (${PRIVATE})...${none}"
#sudo ./ovs-docker add-port $PRIVATE eth1 $CONTAINER2
#retval=$?
#check_retval $retval


echo -en "${blue}Delete previous flow rules...${none}"
sudo ovs-ofctl del-flows $PRIVATE
retval=$?
check_retval $retval


echo -en "${blue}Add flow rules to ${PRIVATE}...${none}"
#L3 routing between
if [ $CONTAINER_BASED -eq 1 ]
then
  sudo ovs-ofctl add-flows $PRIVATE ovsbr-int-dnsfilter.flows
else
  sudo ovs-ofctl add-flows $PRIVATE ovsbr-int-dnsfilter_local.flows
fi
retval=$?
check_retval $retval


echo -en "${blue}Copying filter.py to the / folder of container ${CONTAINER2}...${none}"
sudo docker cp ./filter.py $CONTAINER2:/
retval=$?
check_retval $retval

echo -en "${blue}Copying ML model (${ML_MODEL}) to the / folder of container ${CONTAINER2}...${none}"
sudo docker cp ./$ML_MODEL $CONTAINER2:/
retval=$?
check_retval $retval

echo -en "${blue}Installing extra packages in ${CONTAINER2}...${none}"
sudo docker exec filter apt-get update
sudo docker exec filter apt-get install -y --no-install-recommends python3-numpy python3-sklearn
retval=$?
check_retval $retval






echo -e "${blue}Disabling checksum offloading on all virtual devices...${none}"
for i in $(ip link |grep "@" |grep ovs-system| awk '{print $2}'|cut -d '@' -f 1)
do
	echo -en "\t${i}${none}\t"
	sudo ethtool -K $i tx off rx off 1> /dev/null
	retval=$?
	check_retval $retval
done
echo -e "${blue}Disabling checksum offloading inside the containers...${none}"

echo -en "${blue}in container ${CONTAINER2}...${none}"
sudo docker exec $CONTAINER2 ethtool -K eth0 tx off rx off 1> /dev/null
retval=$?
check_retval $retval

echo -en "${blue}in container ${CONTAINER1}..."
echo -e "${yellow} NOT IN PRIVILEGED mode due to GUI-X11 requirements, skipping...${none}"

