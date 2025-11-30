package scanner

import (
	"bw-pvscan/utils"
	"fmt"
	"net"
	"time"

	"github.com/weppos/publicsuffix-go/publicsuffix"
)

func ScanMenu() {
	utils.ClearScreen()
	fmt.Println(string(utils.ColorWhite) + "\n                                                                                               \n    ▄▄▄     ▄▄▄               ▄▄▄▄▄▄     ▄▄▄         ▄▄▄▄▄    ▄   ▄▄▄▄     ▄▄       ▄▄     ▄▄▄ \n   ██▀▀█▄  █▀██  ██  ██▀▀    █▀██▀▀▀█▄  █▀██  ██▀▀  ██▀▀▀▀█▄  ▀██████▀   ▄█▀▀█▄     ██▄   ██▀  \n   ██ ▄█▀    ██  ██  ██        ██▄▄▄█▀    ██  ██    ▀██▄  ▄▀    ██       ██  ██     ███▄  ██   \n   ██▀▀█▄    ██  ██  ██        ██▀▀▀      ██  ██      ▀██▄▄     ██       ██▀▀██     ██ ▀█▄██   \n ▄ ██  ▄█    ██▄ ██▄ ██      ▄ ██         ██▄ ██    ▄   ▀██▄    ██     ▄ ██  ██     ██   ▀██   \n ▀██████▀    ▀████▀███▀      ▀██▀          ▀███▀    ▀██████▀    ▀█████ ▀██▀  ▀█▄█ ▀██▀    ██   \n                                                                                               \n                                                                                               ")

	utils.PrintCentered(string(utils.ColorRed) + "made by exeller56")
	utils.PrintCentered(string(utils.ColorBlue) + "discord: discord.gg/gNv3QtWrQ5")
	fmt.Println(string(utils.ColorWhite))

	var target string

	fmt.Print("Write target ip address: ")
	fmt.Scanln(&target)
	fmt.Println("")

	Scan(target)

	var exit string

	fmt.Print("Do you want to exit (y/n): ")
	fmt.Scanln(&exit)

	if exit == "y" {
		utils.ClearScreen()
		return
	} else {
		ScanMenu()
	}
}

func Scan(str string) {

	var ipTarget string

	if isDomain(str) {
		resolvedIP, err := DtoIP(str)
		if err != nil {
			fmt.Println("Error resolving domain:", err)
			return
		}
		ipTarget = resolvedIP
	} else if isIPV4(str) {
		ipTarget = str
	}

	config := ScanConfig{
		IP:        ipTarget,
		StartPort: 1,
		EndPort:   65535,
		Timeout:   2 * time.Second,
		Workers:   200,
		ShowTable: true,
	}

	EnhancedPortScanWithShodan(config,
		func(progress float64) {
			fmt.Printf("\rScanning... %.2f%% complete", progress)
		},
		func(result ScanResult) {
			if result.Open {
				fmt.Printf("\rPort %d is open: %s\n", result.Port, result.Service)
			}
		})
}

func isDomain(str string) bool {
	_, err := publicsuffix.Domain(str)
	return err == nil
}

func isIPV4(str string) bool {
	ip := net.ParseIP(str)
	if ip == nil {
		return false
	}
	return ip.To4() != nil
}

func DtoIP(str string) (string, error) {
	ips, err := net.LookupIP(str)
	if err != nil {
		return "", err
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	if len(ips) > 0 {
		return ips[0].String(), nil
	}

	return "", fmt.Errorf("no IP addresses found for %s", str)
}
