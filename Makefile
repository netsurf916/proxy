all: proxy.go socks5/socks5.go
	go fmt proxy.go
	go fmt socks5/socks5.go
	go fmt filter/filter.go
	GO111MODULE=off go build -ldflags="-w -s"
	upx proxy

clean:
	-rm proxy
