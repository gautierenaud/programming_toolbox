FROM ubuntu:16.04

#installation
RUN apt-get update && apt-get install -y \
    apt-utils \
    build-essential \
    socat

#user

RUN useradd -ms /bin/sh get_it
WORKDIR /home/get_it
COPY ./flag.txt ./
COPY ./get_it.c  ./


RUN chown -R root:get_it /home/get_it && \
     chmod 750 /home/get_it && \
     chown root:get_it /home/get_it/flag.txt && \
     chmod 440 /home/get_it/flag.txt && \
     chmod 550 /home/get_it/get_it.c

RUN gcc -fno-stack-protector -o get_it get_it.c 

EXPOSE 1437

ENTRYPOINT ["socat", "-T60", "TCP-LISTEN:1437,reuseaddr,fork,su=get_it","EXEC:/home/get_it/get_it,pty"]
