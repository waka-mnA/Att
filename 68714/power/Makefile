attack : $(wildcard *.[ch])
	@gcc -Wall -std=gnu99 -O3 -o ${@} $(filter %.c, ${^}) -lm -lgmp

.DEFAULT_GOAL = all

all   : attack

clean :
	@rm -f core modmul
