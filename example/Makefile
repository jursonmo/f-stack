TOPDIR=..

ifeq ($(FF_PATH),)
	FF_PATH=${TOPDIR}
endif

ifeq ($(FF_DPDK),)
	FF_DPDK=${TOPDIR}/dpdk/x86_64-native-linuxapp-gcc
endif

#-lfstack, here -L${FF_PATH}/lib, so fstack don't have to install to /usr/local/lib
LIBS+= -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive
LIBS+= -L${FF_DPDK}/lib -Wl,--whole-archive,-ldpdk,--no-whole-archive
LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -pthread -lnuma

TARGET="helloworld"
all:
	cc -O -gdwarf-2  -I../lib -o ${TARGET} main.c ${LIBS}
	cc -O -gdwarf-2  -I../lib -o ${TARGET}_epoll main_epoll.c ${LIBS}
	cc -O -gdwarf-2  -I../lib -o ${TARGET}_client main_client.c ${LIBS}
	cc -O -gdwarf-2  -I../lib -o ${TARGET}_kni main_kni.c ${LIBS} -I${FF_DPDK}/include
.PHONY: clean
clean:
	rm -f *.o ${TARGET} ${TARGET}_epoll ${TARGET}_client ${TARGET}_kni
