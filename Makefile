all: proxy.go socks5/socks5.go
	go fmt proxy.go
	go fmt socks5/socks5.go
	go build -ldflags="-w -s"
	upx proxy
