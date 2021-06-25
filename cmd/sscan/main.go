package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/paulstuart/sscan"
)

func main() {
	var (
		subnet      string
		http, https string
		timeout     string
		ports       []int
		tls         []int
	)
	// flag.StringVar(&gopherType, "gopher_type", defaultGopher, usage)

	flag.StringVar(&subnet, "CIDR", "local", "CIDR to scan, 'local' implies discovered local subnet")
	flag.StringVar(&http, "http", "80,8080", "HTTP network ports to scan")
	flag.StringVar(&https, "tls", "443", "HTTPS network ports to scan")
	flag.StringVar(&timeout, "timeout", "1s", "Time out for pinging port")
	flag.BoolVar(&sscan.Debug, "debug", false, "show error output")
	flag.Parse()

	for _, port := range strings.Split(http, ",") {
		p, err := strconv.Atoi(port)
		if err != nil {
			log.Fatal(err)
		}
		ports = append(ports, p)
	}
	for _, port := range strings.Split(https, ",") {
		p, err := strconv.Atoi(port)
		if err != nil {
			log.Fatal(err)
		}
		tls = append(tls, p)
	}
	duration, err := time.ParseDuration(timeout)
	if err != nil {
		log.Fatal(err)
	}
	sscan.Timeout = duration
	sscan.SetLogger(log.Default())
	log.Printf("scanning %s for http (%v) and https (%v)\n", subnet, ports, tls)
	if err := sscan.Scan(subnet, ports, tls, found); err != nil {
		log.Fatal(err)
	}
}

func found(f sscan.Found) {
	fmt.Println(f)
}
