package sscan

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

const LocalSubnet = "local"

var (
	logger  *log.Logger = log.New(ioutil.Discard, "", 0)
	Timeout             = 10 * time.Second
	Debug   bool
)

func SetLogger(l *log.Logger) {
	logger = l
}

func debugf(msg string, args ...interface{}) {
	if Debug {
		logger.Printf(msg, args...)
	}
}

// Ulimit returns the ulimit of open files on the host
func Ulimit() int64 {
	out, err := exec.Command("sh", "-c", "ulimit -n").Output()
	if err != nil {
		panic(err)
	}
	s := strings.TrimSpace(string(out))
	i, err := strconv.ParseInt(s, 10, 64)

	if err != nil {
		panic(err)
	}
	return i
}

func networkInfo() (*net.IPNet, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet, nil
			}
		}
	}
	return nil, fmt.Errorf("no IP address for you!")
}

func DefaultSubnet() (string, error) {
	n, err := networkInfo()
	if err != nil {
		return "", err
	}
	return n.String(), nil
}

func probes(ip string, http, https []int) []string {
	list := make([]string, len(http)+len(https))
	for i, p := range http {
		list[i] = fmt.Sprintf("http://%s:%d", ip, p)
	}
	for i, p := range https {
		list[i+len(http)] = fmt.Sprintf("https://%s:%d", ip, p)
	}
	return list
}

type Found struct {
	IP      string
	Port    int
	App     string
	Version string
	Vendor  string
	TS      time.Time
}

func scan(fn func(Found), ip string, http, https []int) {
	for _, u := range probes(ip, http, https) {
		if head(u, fn) {
			break
		}
	}
}

func head(probe string, fn func(Found)) bool {
	tr := &http.Transport{
		MaxIdleConns: 10,
		//		IdleConnTimeout:    2 * time.Second,
		DisableCompression: true,
	}
	client := &http.Client{Transport: tr}

	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", probe, nil)
	if err != nil {
		debugf("%s -- (%T) %v\n", probe, err, err)
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		debugf("%s -- (%T) %v\n", probe, err, err)
		return false
	}
	header := resp.Header.Get("server")
	details := strings.Split(header, "/")
	var version, vendor string
	server := details[0]
	if len(details) > 1 {
		versions := strings.Fields(details[1])
		version = versions[0]
		if len(versions) > 1 {
			vendor = strings.Trim(versions[1], "()")
		}
	}

	u, _ := url.Parse(probe)
	port, _ := strconv.Atoi(u.Port())
	ip := strings.Split(u.Host, ":")[0]

	if fn != nil {
		fn(Found{
			IP:      ip,
			Port:    port,
			App:     server,
			Version: version,
			Vendor:  vendor,
			TS:      time.Now().Local(),
		})
	}
	return true
}

func sweep(fn func(Found), n *net.IPNet, limit int64, http, https []int) {
	log.Printf("scanning: %s\n", n)
	var wg sync.WaitGroup
	sem := semaphore.NewWeighted(limit)
	for _, ip := range hosts(n.IP, n) {
		_ = sem.Acquire(context.TODO(), 1)
		wg.Add(1)
		go func(ip string) {
			scan(fn, ip, http, https)
			sem.Release(1)
			wg.Done()
		}(ip)
	}
	wg.Wait()
}

func hosts(ip net.IP, n *net.IPNet) []string {
	var ips []string
	for ip := ip.Mask(n.Mask); n.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ScanContext scans the given subnet/ports and sends hits to `fn`
func ScanContext(ctx context.Context, cidr string, http, https []int, fn func(Found)) error {
	if strings.ToLower(cidr) == LocalSubnet {
		subnet, err := DefaultSubnet()
		if err != nil {
			log.Printf("no local network: %v\n", err)
			return err
		}
		cidr = subnet
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}
	limit := Ulimit()
	limit -= 10
	sweep(fn, ipnet, limit, http, https)
	return nil
}

// Scan scans the given subnet/ports and sends hits to `fn`
func Scan(cidr string, http, https []int, fn func(Found)) error {
	if strings.ToLower(cidr) == LocalSubnet {
		subnet, err := DefaultSubnet()
		if err != nil {
			log.Printf("no local network: %v\n", err)
			return err
		}
		cidr = subnet
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}
	limit := Ulimit()
	limit -= 10
	sweep(fn, ipnet, limit, http, https)
	return nil
}

// Info gets info on individual IP
func Info(probe string) {
	fn := func(f Found) {
		fmt.Printf("FND: %+v\n", f)
	}
	head(probe, fn)
}

type FoundIt func(Found)

type Finder interface {
	AddFound(Found) error
}

func Local(fn FoundIt) {
	network, err := DefaultSubnet()
	if err != nil {
		log.Printf("no local network: %v\n", err)
	}

	_ = Scan(network, []int{80}, []int{443}, fn)
}
