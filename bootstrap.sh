#!/bin/bash

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
  echo -e "${green}Example:./bootstrap.sh -d <DISTRO> ${none}"
  echo -e "\t\t-d <DISTRO>: ubuntu or debian"
  exit
}

DISTRO=""
while getopts "h?d:" opt
do
  case "$opt" in
  h|\?)
    show_help
    ;;
  d)
    DISTRO=$OPTARG
    ;;
  *)
    show_help
    ;;
esac
done

if [ "$DISTRO" == "" ]
then
  echo -e "${red}No distro has been set!"
  show_help
fi

if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "ubuntu" ]
then
  ############# DOCKER ################
  echo -e "${yellow}Installing docker...${none}"
  sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y docker docker-engine docker.io containerd runc
  sudo DEBIAN_FRONTEND=noninteractive apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install \
      apt-transport-https \
      ca-certificates \
      curl \
      gnupg-agent \
      software-properties-common


  curl -fsSL https://download.docker.com/linux/$DISTRO/gpg | sudo apt-key add -

  codename=$(lsb_release -cs)
  if [ "$codename" == "bullseye" ]
  then
    codename=buster #docker has no installation candidate for debian bullseye
  fi
  sudo add-apt-repository \
     "deb [arch=amd64] https://download.docker.com/linux/${DISTRO} \
     $codename stable"

  sudo DEBIAN_FRONTEND=noninteractive apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io

  echo -e "${yellow}Downloading docker images...${none}"
  sudo docker pull cslev/debian_networking:pythonml
  sudo docker pull cslev/docker_firefox:selenium

  ############# OVS ################
  echo -e "${yellow}Installing ovs...${none}"
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y openvswitch-common openvswitch-switch
  sudo systemctl disable openvswitch-switch
  sudo /etc/init.d/openvswitch-switch stop
else
  echo -e "${red}Unsupported distribution has been selected ($DISTRO)!${none}"
  show_help  
fi
