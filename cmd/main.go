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
	Date  string
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

	// var cves []string
	patches := []ubuntuEsmPatches{}
	var dates []string
	var titles []string

	c.OnHTML(".p-heading--four", func(e *colly.HTMLElement) {
		titles = append(titles, e.Text)

		e.ForEach("a[href]", func(_ int, e *colly.HTMLElement) {
			link := e.Attr("href")
			if !strings.HasPrefix(link, "https://usn.ubuntu.com/") {
				return
			}
			c.Visit(e.Request.AbsoluteURL(link))
		})
	})

	c.OnHTML("em", func(e *colly.HTMLElement) {
		dates = append(dates, e.Text)
	})

	// On every a element which has href attribute call callback
	// c.OnHTML("a[href]", func(e *colly.HTMLElement) {
	// 	link := e.Attr("href")
	// 	if strings.HasPrefix(e.Text, "CVE-") {
	// 		// fmt.Println(e.Text, cves)
	// 		for _, item := range cves {
	// 			if item == e.Text {
	// 				return
	// 			}
	// 		}
	// 		cves = append(cves, e.Text)
	// 	}

	// 	if !strings.HasPrefix(link, "https://usn.ubuntu.com/") {
	// 		return
	// 	}
	// 	c.Visit(e.Request.AbsoluteURL(link))
	// })

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL.String())
	})

	c.Visit("https://usn.ubuntu.com/releases/ubuntu-14.04-esm/")
	// c.Visit("https://usn.ubuntu.com/3977-3/")

	for i, t := range titles {
		patch := ubuntuEsmPatches{}
		patch.Title = t
		patch.Date = dates[i]
		patches = append(patches, patch)
	}

	// TODO: logging purpose, needs to be removed.
	fmt.Println(len(titles), len(dates), len(patches))

	enc := json.NewEncoder(os.Stdout)
	enc.Encode(patches)
}
