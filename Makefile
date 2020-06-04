.PHONY: init
init:
	GO111MODULE=off go get -u github.com/caddyserver/xcaddy/cmd/xcaddy

.PHONY: run-test-server
run-test-server:
	xcaddy run --config dev/Caddyfile
