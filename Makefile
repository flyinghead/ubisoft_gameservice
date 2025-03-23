INSTALL_DIR = /usr/local/ubisoft
USER = dcnet

all:
	cd gs_router ; make
	cd gs_lobby ; make

clean:
	cd gs_router ; make clean
	cd gs_lobby ; make clean

install: all
	install -o $(USER) -g $(USER) -d $(INSTALL_DIR)
	install -o $(USER) -g $(USER) gs_router/gs_router $(INSTALL_DIR)
	install -o $(USER) -g $(USER) gs_lobby/gs_lobby gs_lobby/gs_gameserver $(INSTALL_DIR)

installwebsite:
	cp gameloft.site /etc/nginx/sites-availables/gameloft
	ln -s /etc/nginx/sites-available/gameloft /etc/nginx/sites-enabled
	systemctl restart nginx

installservice:
	cd systemd ; make installservice

createdb:
	install -o $(USER) -g $(USER) -d $(INSTALL_DIR)/db
	sqlite3 $(INSTALL_DIR)/db/gs.db < gs_router/db/create_gs.sql
	sqlite3 $(INSTALL_DIR)/db/pod.db < gs_lobby/db/create_pod.sql
	sqlite3 $(INSTALL_DIR)/db/monaco.db < gs_lobby/db/create_monaco.sql
	sqlite3 $(INSTALL_DIR)/db/sdo.db < gs_lobby/db/create_sdo.sql
	chown $(USER):$(USER) $(INSTALL_DIR)/db/*.db
