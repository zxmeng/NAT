make:
	gcc -o nat nat.c checksum.c -lnetfilter_queue
clean:
	\rm -rf nat
