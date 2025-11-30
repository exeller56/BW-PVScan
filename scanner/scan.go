package scanner

import (
	"bw-pvscan/utils"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apcera/termtables"
)

var (
	portServices     map[int]string
	portServicesOnce sync.Once
)

func init() {
	initializePortServices()
}

func initializePortServices() {
	portServicesOnce.Do(func() {
		portServices = make(map[int]string)
		var raw map[string]string
		if err := json.Unmarshal(utils.ScannerTable, &raw); err != nil {
			fmt.Println("bwscan: failed to parse ScannerTable:", err)
			return
		}
		for k, v := range raw {
			if p, err := strconv.Atoi(k); err == nil {
				portServices[p] = v
			}
		}
	})
}

type ScanConfig struct {
	IP        string
	StartPort int
	EndPort   int
	Method    string
	Timeout   time.Duration
	Workers   int
	ShowTable bool
}

type ScanResult struct {
	Port    int
	Open    bool
	Service string
	Error   error
}

type ShodanResponse struct {
	IP          string   `json:"ip"`
	Ports       []int    `json:"ports"`
	Tags        []string `json:"tags"`
	Hostnames   []string `json:"hostnames"`
	Cpes        []string `json:"cpes"`
	Vulns       []string `json:"vulns"`
	ISP         string   `json:"isp"`
	Transport   string   `json:"transport"`
	CountryCode string   `json:"country_code"`
	City        string   `json:"city"`
	LastUpdated string   `json:"last_update"`
}

func EnhancedPortScanWithShodan(config ScanConfig, progressCallback func(progress float64), resultCallback func(ScanResult)) {
	totalPorts := config.EndPort - config.StartPort + 1

	var tablePort *termtables.Table
	if config.ShowTable {
		tablePort = termtables.CreateTable()
		tablePort.AddHeaders("PORT", "SERVICE", "STATUS", "PROTOCOL", "SHODAN INFO")
	}

	fmt.Printf("Querying Shodan for %s...\n", config.IP)
	shodanData := utils.ShodanQuery(config.IP)
	var shodanInfo ShodanResponse
	json.Unmarshal(shodanData, &shodanInfo)

	ports := generatePorts(config.StartPort, config.EndPort)
	results := make(chan ScanResult, totalPorts)

	var wg sync.WaitGroup
	var scanned int32
	var openPorts int32

	if config.Workers <= 0 {
		config.Workers = calculateWorkers(totalPorts)
	}
	if config.Timeout <= 0 {
		config.Timeout = 2 * time.Second
	}
	if config.Method == "" {
		config.Method = "tcp"
	}

	for i := 0; i < config.Workers; i++ {
		wg.Add(1)
		go enhancedPortScannerWorkerWithShodan(config, ports, results, &wg, &scanned, totalPorts, progressCallback, &openPorts, tablePort, shodanInfo)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		resultCallback(result)
	}

	if config.ShowTable && tablePort != nil && atomic.LoadInt32(&openPorts) > 0 {
		fmt.Println("\nScan Results with Shodan Intelligence:")
		fmt.Println(tablePort.Render())
		fmt.Printf("\nTotal open ports: %d\n", atomic.LoadInt32(&openPorts))
		displayShodanInsights(shodanInfo)
	}
}

func enhancedPortScannerWorkerWithShodan(config ScanConfig, ports <-chan int, results chan<- ScanResult, wg *sync.WaitGroup, scanned *int32, total int, progressCallback func(float64), openPorts *int32, tablePort *termtables.Table, shodanInfo ShodanResponse) {
	defer wg.Done()

	for port := range ports {
		target := net.JoinHostPort(config.IP, strconv.Itoa(port))

		methods := []string{config.Method}
		if config.Method == "tcp" {
			methods = append(methods, "tcp4", "tcp6")
		}

		var conn net.Conn
		var err error
		var usedMethod string

		for _, method := range methods {
			conn, err = net.DialTimeout(method, target, config.Timeout)
			if err == nil {
				usedMethod = method
				break
			}
		}

		if err == nil {
			conn.Close()
			service := GetEnhancedService(port, usedMethod)

			result := ScanResult{
				Port:    port,
				Open:    true,
				Service: service,
			}
			results <- result

			if config.ShowTable && tablePort != nil {
				shodanNote := getShodanPortInfo(port, shodanInfo)
				tablePort.AddRow(port, service, "OPEN", usedMethod, shodanNote)
			}

			atomic.AddInt32(openPorts, 1)
		} else {
			results <- ScanResult{
				Port:  port,
				Open:  false,
				Error: err,
			}
		}

		current := atomic.AddInt32(scanned, 1)
		if progressCallback != nil {
			progress := float64(current) / float64(total) * 100
			progressCallback(progress)
		}
	}
}

func getShodanPortInfo(port int, shodanInfo ShodanResponse) string {
	for _, p := range shodanInfo.Ports {
		if p == port {
			notes := []string{}
			if len(shodanInfo.Tags) > 0 {
				notes = append(notes, "Tags: "+strings.Join(shodanInfo.Tags, ","))
			}
			if len(shodanInfo.Vulns) > 0 {
				notes = append(notes, fmt.Sprintf("Vulns: %d", len(shodanInfo.Vulns)))
			}
			if len(notes) > 0 {
				return strings.Join(notes, " | ")
			}
			return "Shodan: Known"
		}
	}
	return ""
}

func displayShodanInsights(shodanInfo ShodanResponse) {
	if len(shodanInfo.Ports) == 0 {
		return
	}

	fmt.Println("\nShodan Intelligence Insights:")
	fmt.Println("================================")

	if len(shodanInfo.Hostnames) > 0 {
		fmt.Printf("Hostnames: %s\n", strings.Join(shodanInfo.Hostnames, ", "))
	}
	if shodanInfo.ISP != "" {
		fmt.Printf("ISP: %s\n", shodanInfo.ISP)
	}
	if shodanInfo.City != "" {
		fmt.Printf("Location: %s, %s\n", shodanInfo.City, shodanInfo.CountryCode)
	}
	if len(shodanInfo.Tags) > 0 {
		fmt.Printf("Tags: %s\n", strings.Join(shodanInfo.Tags, ", "))
	}
	if len(shodanInfo.Cpes) > 0 {
		fmt.Printf("CPEs: %s\n", strings.Join(shodanInfo.Cpes, ", "))
	}
	if len(shodanInfo.Vulns) > 0 {
		fmt.Printf("Vulnerabilities: %d found\n", len(shodanInfo.Vulns))
		for i, vuln := range shodanInfo.Vulns {
			if i < 5 {
				fmt.Printf("   - %s\n", vuln)
			}
		}
		if len(shodanInfo.Vulns) > 5 {
			fmt.Printf("   ... and %d more\n", len(shodanInfo.Vulns)-5)
		}
	}
	if shodanInfo.LastUpdated != "" {
		fmt.Printf("Last Updated: %s\n", shodanInfo.LastUpdated)
	}
}

func GetService(port int) string {
	if service, exists := portServices[port]; exists {
		return service
	}
	return "unknown"
}

func GetEnhancedService(port int, protocol string) string {
	service := GetService(port)
	if service == "unknown" {
		return fmt.Sprintf("unknown/%s", protocol)
	}
	return fmt.Sprintf("%s/%s", service, protocol)
}

func calculateWorkers(totalPorts int) int {
	const maxWorkers = 1000
	const minWorkers = 10

	workers := totalPorts / 100
	if workers < minWorkers {
		return minWorkers
	}
	if workers > maxWorkers {
		return maxWorkers
	}
	return workers
}

func generatePorts(start, end int) <-chan int {
	ports := make(chan int, 1000)
	go func() {
		defer close(ports)
		for port := start; port <= end; port++ {
			ports <- port
		}
	}()
	return ports
}

type ScanStats struct {
	TotalPorts      int
	OpenPorts       int
	KnownServices   int
	UnknownServices int
	Duration        time.Duration
}
