package scraper

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/gocolly/colly"
)

type usnPatches struct {
	Title     string
	Date      string
	CVEs      []string
	CVEScores []cveScore
}

type cveScore struct {
	ID                  string
	Severity            string
	BaseScore           string
	ImpactScore         string
	ExploitabilityScore string
}

// Scrape function gets the USN patches
func Scrape(target string, outputFileName string, displayOption bool) {
	c := colly.NewCollector(
		colly.AllowedDomains("usn.ubuntu.com", "people.canonical.com"),
	)

	c2 := colly.NewCollector(
		colly.AllowedDomains("nvd.nist.gov"),
		colly.AllowURLRevisit(),
	)

	var cves [][]string
	var dates []string
	var titles []string
	patches := []usnPatches{}
	pageHit := 0

	v := []cveScore{}
	vulns := [][]cveScore{}

	c.OnHTML("body.home", func(e *colly.HTMLElement) {
		var sub []string
		vulns = append(vulns, v)

		e.ForEach(".p-heading--four", func(_ int, el *colly.HTMLElement) {
			titles = append(titles, el.Text)

			el.ForEach("a[href]", func(_ int, elem *colly.HTMLElement) {
				link := elem.Attr("href")
				if !strings.HasPrefix(link, "https://usn.ubuntu.com/") {
					return
				}
				err := c.Visit(elem.Request.AbsoluteURL(link))
				if err != nil {
					log.Fatal(err)
				}
			})
		})

		e.ForEach("li", func(_ int, el *colly.HTMLElement) {
			el.ForEach("a[href]", func(_ int, elem *colly.HTMLElement) {
				link := elem.Attr("href")

				if strings.HasPrefix(link, "https://people.canonical.com/~ubuntu-security/cve/") || strings.HasPrefix(elem.Text, "CVE-") {
					sub = append(sub, elem.Text)

					cveScoringLink := "https://nvd.nist.gov/vuln/detail/" + elem.Text
					err := c2.Visit(cveScoringLink)
					if err != nil {
						log.Fatal(err)
					}
				}
			})
		})

		cves = append(cves, sub)
		pageHit++
	})

	c.OnHTML("em", func(e *colly.HTMLElement) {
		dates = append(dates, e.Text)
	})

	c2.OnHTML("div#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnDetailFormPanel", func(e *colly.HTMLElement) {
		vuln := cveScore{}
		e.ForEach("span", func(_ int, el *colly.HTMLElement) {
			attr := el.Attr("data-testid")
			if attr == "page-header-vuln-id" {
				vuln.ID = strings.TrimSpace(el.Text)
			}
			if attr == "vuln-cvssv3-base-score" {
				vuln.BaseScore = strings.TrimSpace(el.Text)
			}
			if attr == "vuln-cvssv3-base-score-severity" {
				vuln.Severity = strings.TrimSpace(el.Text)
			}
			if attr == "vuln-cvssv3-impact-score" {
				vuln.ImpactScore = strings.TrimSpace(el.Text)
			}
			if attr == "vuln-cvssv3-exploitability-score" {
				vuln.ExploitabilityScore = strings.TrimSpace(el.Text)
			}
		})

		vulns[pageHit] = append(vulns[pageHit], vuln)
	})

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL.String())
	})
	c2.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL.String())
	})

	targetURL := "https://usn.ubuntu.com/releases/ubuntu-" + target
	err := c.Visit(targetURL)
	if err != nil {
		log.Fatal(err)
	}

	for i, t := range titles {
		patch := usnPatches{}
		patch.Title = t
		patch.Date = dates[i]
		patch.CVEs = cves[i]
		patch.CVEScores = vulns[i]
		patches = append(patches, patch)
	}

	// jsonData, err := json.Marshal(patches)
	jsonData, err := json.MarshalIndent(patches, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	s := strings.Split(outputFileName, ".")
	if s[len(s)-1] == "json" {
		err := outputJSON(jsonData, outputFileName)
		if err != nil {
			log.Fatal(err)
		}
	}
	// FIXME: output CSV file issue
	// if s[len(s)-1] == "csv" {
	// 	err := outputCSV(patches, outputFileName)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// }
}

func outputJSON(jsonData []byte, outputFileName string) error {
	err := ioutil.WriteFile(outputFileName, jsonData, 0777)
	return err
}

// func outputCSV(data []usnPatches, outputFileName string) error {
// 	// writer := csv.NewWriter()
// 	file, err := os.Create(outputFileName)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer file.Close()

// 	// writer := csv.NewWriter(file)
// 	// defer writer.Flush()

// 	// writer.WriteStruct()

// 	w := csv.NewWriter(file)
// 	err = w.WriteStructAll(data)
// 	return err
// }
