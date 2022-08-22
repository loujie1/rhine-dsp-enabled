package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/semihalev/log"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const configver = "1.2.0"

// Config type
type Config struct {
	Version           string
	CACertificateFile string
	LoggerPubKeyFile  string
}

var defaultConfig = `
# Config version, config and build versions can be different.
version = "%s"

cacertificatefile = "./testdata/certificate/CACert.pem"

loggerpubkeyfile = "./testdata/logger/log.pem"

`

func Load(cfgfile string) (*Config, error) {
	config := new(Config)

	if _, err := os.Stat(cfgfile); os.IsNotExist(err) {
		if path.Base(cfgfile) == "q.conf" {
			// compatibility for old default conf file
			if _, err := os.Stat("q.toml"); os.IsNotExist(err) {
				if err := generateConfig(cfgfile); err != nil {
					return nil, err
				}
			} else {
				cfgfile = "q.toml"
			}
		}
	}

	log.Info("Loading config file", "path", cfgfile)

	if _, err := toml.DecodeFile(cfgfile, config); err != nil {
		return nil, fmt.Errorf("could not load config: %s", err)
	}

	if config.Version != configver {
		log.Warn("Config file is out of version, you can generate new one and check the changes.")
	}

	return config, nil
}

func generateConfig(path string) error {
	output, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("could not generate config: %s", err)
	}

	defer func() {
		err := output.Close()
		if err != nil {
			log.Warn("Config generation failed while file closing", "error", err.Error())
		}
	}()

	r := strings.NewReader(fmt.Sprintf(defaultConfig, configver))
	if _, err := io.Copy(output, r); err != nil {
		return fmt.Errorf("could not copy default config: %s", err)
	}

	if abs, err := filepath.Abs(path); err == nil {
		log.Info("Default config file generated", "config", abs)
	}

	return nil
}
