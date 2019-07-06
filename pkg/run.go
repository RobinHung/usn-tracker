package pkg

import (
	"fmt"
	"log"

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

	if noTarget || noOutput {
		log.Println("USNTracker requires both the `target` and `output` flag.")
		cli.ShowAppHelpAndExit(c, 1)
	}

	return nil
}
