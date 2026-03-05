.PHONY: build build-secops test clean install

build:
	go build -o malakocut ./cmd/malakocut
	go build -o malakocut-cli ./cmd/malakocut-cli

# Future use for conditional compilation if we add heavy cloud SDKs
build-secops:
	go build -tags secops -o malakocut ./cmd/malakocut
	go build -o malakocut-cli ./cmd/malakocut-cli

install: build
	install -m 0755 malakocut /usr/local/bin/malakocut
	install -m 0755 malakocut-cli /usr/local/bin/malakocut-cli
	install -m 0644 malakocut.service /etc/systemd/system/
	mkdir -p /etc/malakocut/configs
	cp configs/*.conf /etc/malakocut/configs/
	cp configs/*.tab /etc/malakocut/configs/
	if [ ! -f /etc/default/malakocut ]; then cp malakocut.env.example /etc/default/malakocut; fi
	systemctl daemon-reload
	@echo "[*] Malakocut installed."
	@echo "[*] Standalone: systemctl enable --now malakocut"
	@echo "[*] SecOps: Edit /etc/default/malakocut, set EXPORTER=secops, then start."

test:
	go test -v ./internal/malakocut/...

clean:
	rm -f malakocut
	rm -f malakocut_debug.log
	rm -rf /tmp/malakocut-test-*
