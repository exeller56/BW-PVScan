package utils

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

var client = &http.Client{
	Transport: &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 8 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 4 * time.Second,
	},
}

func ShodanQuery(ip string) []byte {
	url := "https://internetdb.shodan.io/" + ip

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("We have some error!!! \n Error : %s", err)
		return []byte{}
	}

	reqp, err := client.Do(req)
	if err != nil {
		log.Fatalf("We have some error!!! \n Error : %s", err)
		return []byte{}
	}

	content, err := ioutil.ReadAll(reqp.Body)
	if err != nil {
		log.Fatalf("We have some error!!! \n Error : %s", err)
		return []byte{}
	}

	req.Close = true
	defer reqp.Body.Close()
	if strings.HasPrefix(string(content), `{"error":`) {
		fmt.Println("Warning: Response starts with \"{\"error\":\", this may indicate an error.")
		return []byte{}
	}

	return content
}
