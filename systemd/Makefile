all:

installservice:
	cp ubisoft_lobby@.service ubisoft_router.service /lib/systemd/system/
	systemctl daemon-reload
	systemctl enable ubisoft_router.service
	systemctl enable ubisoft_lobby@pod.service
	systemctl enable ubisoft_lobby@monaco.service
	systemctl enable ubisoft_lobby@sdo.service
