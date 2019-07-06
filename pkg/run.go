package pkg

import (
	"log"
	"strings"

	"github.com/RobinHung/usn-tracker/pkg/scraper"
	"github.com/urfave/cli"
)

// Run function checks the command line arguments
func Run(c *cli.Context) error {
	noTarget := true
	noOutput := true

	target := c.String("target")
	if target != "" {
		// fmt.Println(target)
		noTarget = false
	}

	outputFileName := c.String("output")
	if outputFileName != "" {
		noOutput = false
		s := strings.Split(outputFileName, ".")
		if s[len(s)-1] != "csv" && s[len(s)-1] != "json" {
			log.Fatal("USNTracker only supports `json` or `csv` output.")
		}
	}

	displayOption := c.Bool("display")
	// fmt.Println(displayOption)

	if noTarget || noOutput {
		log.Println("USNTracker requires both the `target` and `output` flag.")
		cli.ShowAppHelpAndExit(c, 1)
	}

	scraper.Scrape(target, outputFileName, displayOption)

	return nil
}
