.PHONY: clean dwarfreader

main: dist dist/agent.so dist/injector dist/loop

dist:
	mkdir dist

dist/agent.so: dist agent.c dwarfreader.o stringutils.o pipecomm.o
	gcc agent.c -o dist/agent.so -shared -fPIC -gdwarf-5 -lpthread dwarfreader.o stringutils.o /usr/local/lib/libdwarf.a -lz pipecomm.o
	
dist/injector: dist dist/agent.so injector.c stringutils.o pipecomm.o
	gcc injector.c -g -o dist/injector stringutils.o pipecomm.o
	
utils.o: utils.c
	gcc -c utils.c -gdwarf-5 -o utils.o

stringutils.o: stringutils.c
	gcc -c stringutils.c -gdwarf-5 -fpic -o stringutils.o

pipecomm.o: pipecomm.c
	gcc -c pipecomm.c -gdwarf-5 -fpic -o pipecomm.o

dwarfreader.o: dwarfreader.c
	gcc -c dwarfreader.c -fpic -gdwarf-5

loop.so: loop.c utils.o
	gcc -shared -fpic loop.c -o loop.so utils.o -gdwarf-5 -fcf-protection=none -fno-omit-frame-pointer

dist/loop: dist loop.c utils.o
	gcc loop.c -gdwarf-5 -o dist/loop utils.o -fcf-protection=none -fno-omit-frame-pointer
	
dist/dwarfreader: dist dwarfreader.c
	gcc dwarfreader.c -o dist/dwarfreader -Llibdwarf -ldwarf -lz -g
	
dwarfreader: dist/dwarfreader

clean:
	! test -f "/tmp/injector.fifo" || sudo rm /tmp/injector.fifo
	rm -f *.o
	rm -f *.so
	rm -rf dist
