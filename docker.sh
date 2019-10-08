#!/bin/bash

# Docker registry + image
DREG=extgit.iaik.tugraz.at:8443
DREGUSER=sasd2019
DREGTOKEN=wv4E5gxeALEgcK9esTyz
DIMG=${DREG}/sase/practicals/docker:sasd2019

RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color


function error {
  printf "${RED}$*${NC}\n"
}

function warning {
  printf "${YELLOW}$*${NC}\n"
}

function info {
  printf "${BLUE}$*${NC}\n"
}

# This function pulls the latest sasd Docker image from the upstream
# Docker registry
function docker_update {
  retval=0
  echo "Logging into Docker registry"
  docker login -u ${DREGUSER} -p ${DREGTOKEN} ${DREG} || retval=$?
  echo "Pulling Docker image"
  docker pull ${DIMG} || retval=$?
  docker logout ${DREG} || retval=$?
  echo "Trying to run Docker image"
  docker run -t ${DIMG} /usr/bin/whoami &> /dev/null || retval=$?
  if [[ "$retval" -ne "0" ]]; then
    error "Unable to update Docker image ${DREG}"
    exit 1
  else
    echo "Successfully updated Docker image:"
    docker image inspect ${DIMG} | grep Created
  fi
}



if [[ "$#" -eq "0" || "$1" == "help" ]]; then
  # Show help
  echo "This script runs your code inside Docker"
  echo ""
  echo "$0 help       Show this help"
  echo "$0 update     Pull the latest Docker image from the sasd2019 registry"
  echo "$0 run [<dir>]  Run Docker inside the current directory, or <dir>, if provided"
  echo ""
  exit 0
elif [[ "$1" == "update" ]]; then
  # Force an update of the Docker image
  docker_update
  exit 0
elif [[ "$1" == "run" ]]; then
  if [[ -d "$2" ]]; then
    # Change working directory
    cd $2
  fi
else
  warning "Invalid arguments! Consult '$0 help'"
  exit 1
fi

# Check if Docker is installed
docker --help &> /dev/null
if [[ "$?" -ne "0" ]]; then
  warning "Please install 'docker'"
  exit 1
fi

# Check if Docker image is available
docker run -t ${DIMG} /usr/bin/whoami &> /dev/null
if [[ "$?" -ne "0" ]]; then
  warning "Docker image missing"
  docker_update
fi

info "Running Docker"
warning "Please observe the following:"
info "1. Your current folder $PWD is mounted as /mnt/host"
info "   Changes inside /mnt/host will be visible when you leave Docker"
info "2. Your current folder is copied to /sasd"
info "   Changes to /sasd will be lost when you leave Docker"
info "3. Hacklets are executed as 'exploit user' with appropriate file"
info "   permissions. To simulate this, run 'execute_permission.sh'"
info "4. To switch to the sasd user, execute 'su sasd'"

# We mount current directory to /mnt/host inside Docker. 
# Be careful! Changes in /mnt/host will show up on the host system

# We make a temporary copy of /mnt/host in /sasd
CMD="mkdir sasd; cd sasd; cp -r /mnt/host/. .; "
# If you run this script inside a hacklet directory, we will execute the hacklet
CMD+="[[ -f execute_permission.sh ]] && ./execute_permission.sh; "
# We will drop a root shell for you to experiment with
CMD+="zsh; "

# Run Docker
docker run -v ${PWD}:/mnt/host -it ${DIMG} /bin/bash -c "${CMD}"
