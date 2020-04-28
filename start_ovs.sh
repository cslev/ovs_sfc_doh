#!/bin/bash
#set here which binaries you want to use!
OVS_MODULE_NAME="openvswitch"


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


function show_help
{
  echo -e "${red}${bold}Arguments not set properly!${none}"
  echo -e "${green}Example: sudo ./start_ovs.sh -n ovsbr ${none}"
  echo -e "\t\t-n <name>: name of the OVS bridge"
  echo -e "\t\t-d <path_to_db.sock>: Path where db.sock will be created!"

  exit
}

DBR=""

while getopts "h?n:d:" opt
do
  case "$opt" in
  h|\?)
    show_help
    ;;
  n)
    DBR=$OPTARG
    ;;
  d)
   DB_SOCK=$OPTARG
    ;;
  *)
    show_help
   ;;
  esac
done

if [[ "$DBR" == "" ]]
then
  show_help
fi

if [[ "$DB_SOCK" == "" ]]
then
  DB_SOCK=/var/run/openvswitch
  echo -e "${yellow}No DB_SOCK has been set, using defaults (${DB_SOCK}/db.sock)${none}"
fi

sudo mkdir -p $DB_SOCK
DB_SOCK="${DB_SOCK}/db.sock"


ptcp_port=16633
echo -ne "${yellow}Adding OVS kernel module${none}"
sudo rmmod $OVS_MODULE_NAME > /dev/null 2>&1
sudo modprobe $OVS_MODULE_NAME  2>&1

echo -e "\t\t${bold}${green}[DONE]${none}"


echo -ne "${yellow}Delete preconfigured ovs data${none}"
sudo rm -rf /etc/openvswitch/conf.db 2>&1
echo -e "\t\t${bold}${green}[DONE]${none}"

sudo mkdir -p /etc/openvswitch/

echo -ne "${yellow}Create ovs database structure${none}"
sudo ovsdb-tool create /etc/openvswitch/conf.db  /usr/share/openvswitch/vswitch.ovsschema
echo -e "\t\t${bold}${green}[DONE]${none}"

sudo mkdir -p /var/run/openvswitch

echo -ne "${yellow}Start ovsdb-server...${none}"
  sudo ovsdb-server --remote=punix:$DB_SOCK --remote=db:Open_vSwitch,Open_vSwitch,manager_options --pidfile --detach
echo -e "\t\t${bold}${green}[DONE]${none}"

echo -e "Initializing..."
sudo ovs-vsctl --no-wait init


sudo ovs-vswitchd unix:$DB_SOCK --pidfile --detach
echo -e "${bold}${green}\t\t[DONE]${none}"


echo -ne "${yellow}Create bridge (${DBR})${none}"
sudo ovs-vsctl add-br $DBR
echo -e "${bold}${green}\t\t[DONE]${none}"

#echo -ne "${yellow}Deleting flow rules from ${DBR}${none}"
#sudo ovs-ofctl del-flows $DBR
#echo -e "${bold}${green}\t\t[DONE]${none}"


echo -ne "${yellow}Add passive controller listener port on ${ptcp_port}${none}"
sudo ovs-vsctl set-controller $DBR ptcp:$ptcp_port
echo -e "\t\t${bold}${green}[DONE]${none}"

echo -e "OVS (${DBR}) has been fired up!"
sudo ovs-vsctl show
echo -e "${none}"
