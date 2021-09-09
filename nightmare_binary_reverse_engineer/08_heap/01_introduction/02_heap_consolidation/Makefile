CC=gcc
CFLAGS=-g -Wall
OUT_NAME=out
IMAGE_NAME=build_and_debug

.PHONY: debug docker docker.run

debug:
	(docker run --rm -v ${PWD}:/source -p 2222:2222 $(IMAGE_NAME) /bin/bash -c \
		"$(CC) $(CFLAGS) *.c -o $(OUT_NAME) && gdbserver localhost:2222 $(OUT_NAME)" &)
	sleep 1 && gdb $(OUT_NAME) -x .gdbsetup

docker:
	docker build -t $(IMAGE_NAME) .

docker.run:
	docker run --rm -it -v ${PWD}:/source -p 2222:2222 $(IMAGE_NAME) /bin/bash