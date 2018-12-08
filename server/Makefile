prechroot.so: prechroot.c
	$(CC) -Os -fPIC -shared -W -o $@ $< -ldl
	[ "`which strip`" = "" ] || strip --strip-all $@

install: prechroot.so
	install -m 644 $+ /usr/lib/
	install -m 750 -D start-sbackup /usr/local/sbin/start-sbackup

uninstall:
	$(RM) /usr/lib/prechroot.so
	$(RM) /usr/local/sbin/start-sbackup

clean:
	$(RM) prechroot.so
