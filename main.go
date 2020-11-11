package main

import (
	"flag"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/mmcloughlin/professor"
	"github.com/prologic/eris/irc"
)

func main() {
	var (
		version    bool
		debug      bool
		configfile string
	)

	flag.BoolVar(&version, "v", false, "display version information")
	flag.BoolVar(&debug, "d", false, "enable debug logging")
	flag.StringVar(&configfile, "c", "ircd.yml", "config file")
	flag.Parse()

	if version {
		fmt.Printf(irc.FullVersion())
		os.Exit(0)
	}

	if debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}

	if debug {
		go professor.Launch(":6060")
	}

	config, err := irc.LoadConfig(configfile)
	if err != nil {
		log.Fatal("Config file did not load successfully:", err.Error())
	}

	irc.NewServer(config).Run()
}
