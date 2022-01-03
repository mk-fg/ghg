LDLIBS = -cclib -lsodium -ccopt -Wl,--no-as-needed

all: ghg

ghg: ghg.ml ghg.ml.c
	ocamlopt -o $@ -O2 unix.cmxa str.cmxa $(LDLIBS) $^
	strip $@

clean:
	rm -f ghg ghg.cmi ghg.cmx ghg.ml.o ghg.o

test:
	./test.sh -x >/dev/null

.SUFFIXES: # to disable built-in rules for %.c and such
