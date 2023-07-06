all: cmd/abuser/main.go
	[ ! -d bin ] && mkdir bin/ || true
	go build -trimpath -o bin/abuser cmd/abuser/main.go
