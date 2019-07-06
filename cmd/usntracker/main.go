package main

import (
	"log"
	"os"

	"github.com/RobinHung/usn-tracker/pkg"
	"github.com/urfave/cli"
)

type ubuntuEsmPatches struct {
	Title     string
	Date      string
	CVEs      []string
	CVEScores []cve
}

type cve struct {
	ID                  string
	BaseScore           string
	Severity            string
	ImpactScore         string
	ExploitabilityScore string
}

func newApp(appname string) *cli.App {
	cli.AppHelpTemplate = `NAME:
	{{.Name}}{{if .Usage}} - {{.Usage}}{{end}}
USAGE:
	{{if .UsageText}}{{.UsageText}}{{else}}{{.HelpName}} {{if .VisibleFlags}}[options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}{{end}}{{if .Version}}{{if not .HideVersion}}
VERSION:
	{{.Version}}{{end}}{{end}}{{if .Description}}
DESCRIPTION:
	{{.Description}}{{end}}{{if len .Authors}}
AUTHOR{{with $length := len .Authors}}{{if ne 1 $length}}S{{end}}{{end}}:
	{{range $index, $author := .Authors}}{{if $index}}
	{{end}}{{$author}}{{end}}{{end}}{{if .VisibleCommands}}
OPTIONS:
	{{range $index, $option := .VisibleFlags}}{{if $index}}
	{{end}}{{$option}}{{end}}{{end}}
`
	app := cli.NewApp()
	app.Name = "USNTracker"
	app.Usage = "Ubuntu Security Notices Tracker"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "target, t",
			Value: "",
			Usage: "ubuntu version to track",
		},
		cli.StringFlag{
			Name:  "output, o",
			Usage: "output file name, only supports json or csv file format",
		},
		cli.BoolFlag{
			Name:  "display, d",
			Usage: "display the result",
		},
	}
	// app.Commands = []cli.Command{}
	app.Action = pkg.Run
	return app
}

func main() {
	if err := newApp("USNTracker").Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
