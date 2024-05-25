package flag

import "github.com/urfave/cli"

var (
	NewFlage = cli.BoolFlag{
		Name:  "new",
		Usage: "generate new keystore",
	}

	AllFlags = []cli.Flag{
		NewFlage,
	}
)
