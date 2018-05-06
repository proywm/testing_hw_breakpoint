EXES= test11
all: $(EXES)

test%: test%.c
	gcc -g -O2 -std=gnu99 perf_parser.c $^ -o $@

check: $(EXES)
	./test11

clean: 
	rm -f $(EXES)
