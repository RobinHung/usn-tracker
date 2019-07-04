package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/gocolly/colly"
)

type ubuntuEsmPatches struct {
	Title string
	CVEs  []string
}

type cve struct {
	ID                  string
	BaseScore           string
	ImpactScore         string
	ExploitabilityScore string
}

func main() {
	c := colly.NewCollector(
		colly.AllowedDomains("usn.ubuntu.com", "people.canonical.com"),
		// colly.MaxDepth(3),
	)

	var cves []string

	// On every a element which has href attribute call callback
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")

		// fmt.Printf("Link found: %q -> %s\n", e.Text, link)
		// fmt.Println(link)

		if strings.HasPrefix(e.Text, "CVE-") {
			// fmt.Println(e.Text, cves)
			for _, item := range cves {
				if item == e.Text {
					return
				}
			}
			cves = append(cves, e.Text)
		}

		// if !strings.HasPrefix(link, "https://usn.ubuntu.com/") && !strings.HasPrefix(link, "https://people.canonical.com/~ubuntu-security/cve") {
		// 	return
		// }
		if !strings.HasPrefix(link, "https://usn.ubuntu.com/") {
			return
		}
		c.Visit(e.Request.AbsoluteURL(link))
	})

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL.String())
	})

	c.Visit("https://usn.ubuntu.com/releases/ubuntu-14.04-esm/")
	// c.Visit("https://usn.ubuntu.com/3977-3/")

	enc := json.NewEncoder(os.Stdout)
	enc.Encode(cves)
}
