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

	var cves [][]string
	patches := []ubuntuEsmPatches{}
	var dates []string
	var titles []string

	c.OnHTML("em", func(e *colly.HTMLElement) {
		dates = append(dates, e.Text)
	})

	c.OnHTML("body.home", func(e *colly.HTMLElement) {
		var subString []string

		e.ForEach(".p-heading--four", func(_ int, el *colly.HTMLElement) {
			titles = append(titles, el.Text)

			el.ForEach("a[href]", func(_ int, elem *colly.HTMLElement) {
				link := elem.Attr("href")
				if !strings.HasPrefix(link, "https://usn.ubuntu.com/") {
					return
				}
				c.Visit(elem.Request.AbsoluteURL(link))
			})
		})

		e.ForEach("li", func(_ int, el *colly.HTMLElement) {
			el.ForEach("a[href]", func(_ int, elem *colly.HTMLElement) {
				link := elem.Attr("href")
				if strings.HasPrefix(link, "https://people.canonical.com/~ubuntu-security/cve/") && strings.HasPrefix(elem.Text, "CVE-") {
					subString = append(subString, elem.Text)
				}
			})
		})

		cves = append(cves, subString)
	})

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL.String())
	})

	c.Visit("https://usn.ubuntu.com/releases/ubuntu-14.04-esm/")

	for i, t := range titles {
		patch := ubuntuEsmPatches{}
		patch.Title = t
		patch.Date = dates[i]
		patch.CVEs = cves[i]
		patches = append(patches, patch)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.Encode(patches)
}
