package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/ethereum/go-ethereum/console/prompt"
	"github.com/urfave/cli"
	"github.com/zwalo/z-nektar/zlog"
	"github.com/zwalo/z-terra/cmd"
	"github.com/zwalo/z-terra/flag"
)

var app = cli.NewApp()

func init() {

	app.Name = filepath.Base(os.Args[0])

	app.Usage = "Generate KeyStore"

	app.Action = func(ctx *cli.Context) error {
		return nil
	}

	app.HideVersion = true // we have a command to print the version
	app.Commands = cmd.Commands
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Flags = flag.AllFlags

	app.CommandNotFound = func(ctx *cli.Context, s string) {
		cli.ShowAppHelp(ctx)
		fmt.Printf("Error: Unknown command \"%v\"\n", s)
		os.Exit(1)
	}

	app.OnUsageError = func(context *cli.Context, err error, isSubcommand bool) error {
		cli.ShowAppHelp(context)
		return err
	}

	app.Before = func(ctx *cli.Context) error {
		return nil
	}

	app.After = func(ctx *cli.Context) error {
		prompt.Stdin.Close() // Resets terminal mode.
		return nil
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		zlog.Fatal(os.Stderr, err)
	}
}
