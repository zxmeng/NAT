make:
	gcc -Wall -o nat nat.c checksum.c -lnetfilter_queue -lnfnetlink
clean:
	\rm -rf nat
