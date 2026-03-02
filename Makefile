.PHONY: build test clean

build:
	go build -o malakocut ./cmd/malakocut

install: build
	install -m 0755 malakocut /usr/local/bin/malakocut
	cp malakocut.service /etc/systemd/system/
	if [ ! -f /etc/default/malakocut ]; then cp malakocut.env /etc/default/malakocut; fi
	systemctl daemon-reload
	@echo "[*] Malakocut installed. Update /etc/default/malakocut then run: systemctl enable --now malakocut"

test:
	go test -v ./internal/malako/...

clean:
	rm -f malakocut
	rm -f malakocut_debug.log
	rm -rf /tmp/malakocut-test-*
