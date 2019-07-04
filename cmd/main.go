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
	count := 0
	pageCount := 0

	// c.OnHTML(".p-heading--four", func(e *colly.HTMLElement) {
	// 	titles = append(titles, e.Text)

	// 	e.ForEach("a[href]", func(_ int, el *colly.HTMLElement) {
	// 		link := el.Attr("href")
	// 		if !strings.HasPrefix(link, "https://usn.ubuntu.com/") {
	// 			return
	// 		}
	// 		// if strings.HasPrefix(link, "CVE-") {
	// 		// 	subString = append(subString, link)
	// 		// 	fmt.Println("sub string: ", subString)
	// 		// }
	// 		c.Visit(el.Request.AbsoluteURL(link))
	// 	})
	// })

	c.OnHTML("em", func(e *colly.HTMLElement) {
		dates = append(dates, e.Text)
	})

	c.OnHTML("body.home", func(e *colly.HTMLElement) {
		fmt.Println("page count: ", pageCount)
		pageCount++
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

		// FIXME: cves bug needs to be fixed!
		e.ForEach("li", func(_ int, el *colly.HTMLElement) {
			// var subString []string
			el.ForEach("a[href]", func(_ int, elem *colly.HTMLElement) {
				link := elem.Attr("href")
				if strings.HasPrefix(link, "https://people.canonical.com/~ubuntu-security/cve/") && strings.HasPrefix(elem.Text, "CVE-") {
					// fmt.Println(e.Text)
					subString = append(subString, elem.Text)
					fmt.Println("sub string: ", subString, count)
					count++
				}
			})
			// cves = append(cves, subString)
		})

		cves = append(cves, subString)
	})

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL.String())
	})

	c.Visit("https://usn.ubuntu.com/releases/ubuntu-14.04-esm/")
	// c.Visit("https://usn.ubuntu.com/3977-3/")

	// TODO: needs to be removed
	fmt.Println("CVEs: ", cves)

	for i, t := range titles {
		patch := ubuntuEsmPatches{}
		patch.Title = t
		patch.Date = dates[i]
		patch.CVEs = cves[i]
		patches = append(patches, patch)
	}

	// TODO: logging purpose, needs to be removed.
	fmt.Println(len(titles), len(dates), len(patches))

	enc := json.NewEncoder(os.Stdout)
	enc.Encode(patches)
}
