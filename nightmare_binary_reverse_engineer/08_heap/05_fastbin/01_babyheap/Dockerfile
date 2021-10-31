FROM ubuntu:16.04

RUN apt-get update && apt-get install build-essential gdb software-properties-common wget curl -y

RUN wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | bash

RUN add-apt-repository ppa:deadsnakes/ppa

RUN apt-get update && apt-get install python3.8 python3.8-distutils git libssl-dev libffi-dev -y

RUN update-alternatives --remove python /usr/bin/python2
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.8 10

RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python3.8 get-pip.py

RUN python3.8 -m pip install --upgrade pip

RUN python3.8 -m pip install --upgrade pwntools

WORKDIR /tmp