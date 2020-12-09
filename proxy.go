package main

import (
	"flag"
	"fmt"
	"net"
	"proxy/socks5"
	"strconv"
)

func logger(ctx socks5.Context) {
	for {
		line, ok := <-ctx.Logger
		if !ok {
			return
		}
		fmt.Print(line)
	}
}

func main() {
	// Process command line arguments
	addrPtr := flag.String("addr", "", "The local IP to bind to.")
	portPtr := flag.Int("port", 3128, "The port to listen on.")
	hostPtr := flag.String("host", "0.0.0.0", "Public address of the proxy (IP or hostname).")
	proxiesPtr := flag.String("proxies", "", "A JSON formatted file containing outbound proxies to use.")
	blacklistPtr := flag.String("blacklist", "blacklist.json", "Blacklist file to use (JSON formatted).")
	updateblacklistPtr := flag.String("updateblacklist", "", "File containing additional blacklist URLs to import.")
	updateblacklistURLPtr := flag.String("updateblacklisturl", "", "URL with additional blacklist URLs to import.")
	flag.Parse()

	// Socks5 context
	var Socks5Ctx socks5.Context

	// Determine which IP to use

	ips, err := net.LookupIP(*hostPtr)
	if err != nil {
		fmt.Printf(" [!] Unable to determine IP: %s\n", *hostPtr)
		return
	}
	Socks5Ctx.ReportIP = ips[0] // Select the first IP returned
	fmt.Printf(" [+] IP to report: %s\n", Socks5Ctx.ReportIP.String())

	// Create a channel for logging
	Socks5Ctx.Logger = make(chan string, 100)

	// Create a channel to transfer inbound connections
	Socks5Ctx.ClientConnections = make(chan socks5.ClientCtx, 10)

	// Setup connection string
	Socks5Ctx.ListenAddress = *addrPtr + ":" + strconv.Itoa(*portPtr)

	// Load list of outbound proxies to cycle between
	if len(*proxiesPtr) > 0 {
		if Socks5Ctx.Proxies.LoadFile(*proxiesPtr) {
			fmt.Printf(" [+] Loaded %d outbound proxies.\n", len(Socks5Ctx.Proxies.Hosts))
			fmt.Printf(" [+] IP will be reported from the remote proxy.\n")
		} else {
			fmt.Printf(" [!] Failed to load proxies from: %s\n", *proxiesPtr)
			fmt.Printf(" [+] Continuing to run without relay proxies.")
		}
	}

	// Initialize the filter
	if !Socks5Ctx.DomainFilter.LoadFile(*blacklistPtr) {
		// Load some external blacklists to create the initial list
		/*
			ExternalLists := []string{
				"https://mirror1.malwaredomains.com/files/justdomains",
				"http://www.malwaredomainlist.com/hostslist/hosts.txt"
			}
			ok, count := Socks5Ctx.DomainFilter.LoadHTTP("")
			if ok {
				fmt.Printf(" [+] Loaded %d domains from: \"https://mirror1.malwaredomains.com/files/justdomains\"\n", count)
			} else {
				fmt.Printf(" [!] Error loading blacklist: \"https://mirror1.malwaredomains.com/files/justdomains\"\n")
			}
		*/
	}
	if len(*updateblacklistPtr) > 0 {
		ok, count := Socks5Ctx.DomainFilter.LoadListFile(*updateblacklistPtr)
		if ok {
			fmt.Printf(" [+] Loaded %d domains from: \"%s\"\n", count, *updateblacklistPtr)
		} else {
			fmt.Printf(" [+] Error loading blacklist: \"%s\"\n", *updateblacklistPtr)
		}
	}
	if len(*updateblacklistURLPtr) > 0 {
		ok, count := Socks5Ctx.DomainFilter.LoadHTTP(*updateblacklistURLPtr)
		if ok {
			fmt.Printf(" [+] Loaded %d domains from: \"%s\"\n", count, *updateblacklistURLPtr)
		} else {
			fmt.Printf(" [+] Error loading blacklist: \"%s\"\n", *updateblacklistURLPtr)
		}
	}
	// Always write it back out to save changes (additions, deduplications, etc)
	Socks5Ctx.DomainFilter.SaveFile(*blacklistPtr)
	fmt.Printf(" [*] Blacklist contains %d domains\n", len(Socks5Ctx.DomainFilter.Domains))

	// Start a background thread to handle logging
	go logger(Socks5Ctx)

	// Start background thread to handle clients
	go Socks5Ctx.HandleClients()

	// Listen for inbound connections
	Socks5Ctx.Listen()
}
