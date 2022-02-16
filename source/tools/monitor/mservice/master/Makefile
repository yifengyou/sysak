DIRS = src modules

all:
	for i in $(DIRS); do make -C $$i; done

clean:
	for i in $(DIRS); do cd $$i;make clean;cd ..; done

install: all
	#mkdir for mservice
	mkdir -p $(INSTALL_PRE)/monitor/modules
	#copy shared so
	cp modules/*.so $(INSTALL_PRE)/monitor/modules/
	#copy bin file
	cp src/mservice $(INSTALL_PRE)/
	#copy config file
	cp conf/sysakmon.conf $(INSTALL_PRE)/monitor/

uninstall:
	#rm tsar
	rm -rf $(INSTALL_PRE)/monitor/
	rm -rf $(INSTALL_PRE)/mservice
	
.PHONY: all clean install unintall
