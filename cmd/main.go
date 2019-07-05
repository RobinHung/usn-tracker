package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
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
	Severity            string
	ImpactScore         string
	ExploitabilityScore string
}

func main() {
	c := colly.NewCollector(
		colly.AllowedDomains("usn.ubuntu.com", "people.canonical.com"),
		// colly.MaxDepth(3),
	)

	c2 := colly.NewCollector(
		colly.AllowedDomains("nvd.nist.gov"),
	)

	var cves [][]string
	patches := []ubuntuEsmPatches{}
	var dates []string
	var titles []string

	vulns := []cve{}

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

					cveScoringLink := "https://nvd.nist.gov/vuln/detail/" + elem.Text
					c2.Visit(cveScoringLink)
				}
			})
		})

		cves = append(cves, subString)
	})

	c2.OnHTML("div#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnDetailFormPanel", func(e *colly.HTMLElement) {
		vuln := cve{}
		e.ForEach("span", func(_ int, el *colly.HTMLElement) {
			attr := el.Attr("data-testid")
			if attr == "page-header-vuln-id" {
				// fmt.Println(el.Text)
				vuln.ID = el.Text
			}
			if attr == "vuln-cvssv3-base-score" {
				// fmt.Println(el.Text)
				vuln.BaseScore = el.Text
			}
			if attr == "vuln-cvssv3-base-score-severity" {
				vuln.Severity = el.Text
			}
			if attr == "vuln-cvssv3-impact-score" {
				vuln.ImpactScore = strings.TrimSpace(el.Text)
			}
			if attr == "vuln-cvssv3-exploitability-score" {
				vuln.ExploitabilityScore = strings.TrimSpace(el.Text)
			}
		})

		vulns = append(vulns, vuln)
	})

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL.String())
	})
	c2.OnRequest(func(r *colly.Request) {
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

	fmt.Println(vulns, len(vulns))

	// Print out json data
	// enc := json.NewEncoder(os.Stdout)
	// enc.Encode(patches)

	jsonData, err := json.Marshal(patches)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("trusty-esm-patches.json", jsonData, 0777)
	if err != nil {
		log.Fatal(err)
	}
}
