FROM debian:stretch

RUN apt-get update \
    && apt-get install -y g++ build-essential gdb gdbserver openssh-server

WORKDIR /source

EXPOSE 2222
