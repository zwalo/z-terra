package cmd

import (
	"github.com/urfave/cli"
	"github.com/zwalo/z-terra/flag"
	"github.com/zwalo/z-terra/keystore"
)

var Commands = []cli.Command{
	{
		Action: migrateFlags(keystore.Command),
		Name:   "gen",
		Usage:  "generate keystore",
		Flags: []cli.Flag{
			flag.NewFlage,
		},
		Category:    "generate-key",
		Description: `generate keystore`,
	},
}

func migrateFlags(action func(ctx *cli.Context) error) func(*cli.Context) error {
	return func(ctx *cli.Context) error {
		for _, name := range ctx.FlagNames() {
			if ctx.IsSet(name) {
				ctx.GlobalSet(name, ctx.String(name))
			}
		}
		return action(ctx)
	}
}
