package main

import (
	"bufio"
	"encoding/json"
	"fmt"
// 	"github.com/andlabs/ui"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
)

type Cve struct {
	CVEID        string `json:"cve_id"`
	CWEID        int    `json:"cwe_id"`
	Summary      string
	ExploitCount int    `json:"exploit_count"`
	PublishDate  string `json:"publish_date"`
	UpdateDate   string `json:"update_date"`
	URL          string
}

func matchSCML(softw string) bool {
	a := false
	f, err := os.Open("softwareListSCML")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		c := scanner.Text()
		r, err := regexp.Compile(c)

		if err != nil {
			fmt.Printf("There is a problem with your regexp.\n")
		}
		if r.MatchString(softw) == true {
			a = true
		}
	}

	return a
}

func main() {

	//get cve list
	res, err := http.Get("http://www.cvedetails.com/json-feed.php?numrows=30&vendor_id=0&product_id=0&version_id=0&hasexp=0&opec=0&opov=0&opcsrf=0&opfileinc=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opginf=0&opdos=0&orderby=2&cvssscoremin=4")
	if err != nil {
		log.Fatal(err)
	}

	//read the results to a variable
	data, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	var cves []Cve

	err = json.Unmarshal(data, &cves)

	for i := 0; i < len(cves); i++ {

		if matchSCML(cves[i].Summary) == true {
			fmt.Println("+ + +")
			fmt.Println("CVE-ID:", cves[i].CVEID)
			fmt.Println("Summary:", cves[i].Summary)
			fmt.Println("Publish Date:", cves[i].PublishDate)
			fmt.Println("+ + +")
		}
	}
}
