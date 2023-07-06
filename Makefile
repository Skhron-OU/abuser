all: cmd/abuser/main.go
	go build -trimpath -o bin/abuser cmd/abuser/main.go
