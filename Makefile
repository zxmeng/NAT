make:
	gcc -o nat nat.c checksum.c -lnetfilter_queue -lnfnetlink
clean:
	\rm -rf nat
