.PHONY: init
init:
	go get install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

.PHONY: run-test-server
run-test-server:
	xcaddy run --config dev/Caddyfile
