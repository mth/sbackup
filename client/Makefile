INSTALL_DIR=/etc/sbackup

reverse-pipe: reverse-pipe.c
	$(CC) -std=c99 -W -Wall -o $@ -O3 $<
	[ "`which strip`" = "" ] || strip --strip-all $@

clean:
	rm -f reverse-pipe

install: install-bin /etc/sbackup/sbackup.conf
	@echo 'Add into ~sbackup/.ssh/authorized_keys the backup server key with'
	@echo 'command="sudo $(INSTALL_DIR)/reverse-sshfs-backup"'

install-bin: rsync-backup dmcrypt-backup reverse-sshfs-backup reverse-pipe
	mkdir -p $(INSTALL_DIR)
	chmod 700 $(INSTALL_DIR)
	install -o 0 -g 0 -m 700 $+ $(INSTALL_DIR)/

/etc/sbackup/sbackup.conf: sbackup.conf
	[ -f $@ ] || install -o 0 -g 0 -m 600 -T $< $@
