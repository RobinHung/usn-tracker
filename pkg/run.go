package pkg

import (
	"fmt"
	"log"

	"github.com/RobinHung/usn-tracker/pkg/scraper"
	"github.com/urfave/cli"
)

// Run function checks the command line arguments
func Run(c *cli.Context) error {
	noTarget := true
	noOutput := true

	target := c.String("target")
	if target != "" {
		fmt.Println(target)
		noTarget = false
	}

	outputFileName := c.String("output")
	if outputFileName != "" {
		fmt.Println(outputFileName)
		noOutput = false
	}

	displayOption := c.Bool("display")
	fmt.Println(displayOption)

	if noTarget || noOutput {
		log.Println("USNTracker requires both the `target` and `output` flag.")
		cli.ShowAppHelpAndExit(c, 1)
	}

	scraper.Scrape(target, outputFileName, displayOption)

	return nil
}
