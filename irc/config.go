package irc

import (
	"errors"
	"io/ioutil"
	"log"
	"sync"

	"github.com/imdario/mergo"
	"gopkg.in/yaml.v2"
)

type PassConfig struct {
	Password string
}

type TLSConfig struct {
	Key  string
	Cert string
}

type I2PConfig struct {
	I2Pkeys string
	SAMaddr string
	Base32  string
}

type TorConfig struct {
	Torkeys     string
	ControlPort int
	Onion       string
}

func (conf *PassConfig) PasswordBytes() []byte {
	bytes, err := DecodePassword(conf.Password)
	if err != nil {
		log.Fatal("decode password error: ", err)
	}
	return bytes
}

type Config struct {
	sync.Mutex
	filename string

	Network struct {
		Name string
	}

	Server struct {
		PassConfig  `yaml:",inline"`
		Listen      []string
		TLSListen   map[string]*TLSConfig
		I2PListen   map[string]*I2PConfig
		TorListen   map[string]*TorConfig
		Log         string
		MOTD        string
		Name        string
		Description string
	}

	WWW struct {
		Listen    []string
		TLSListen map[string]*TLSConfig
		I2PListen map[string]*I2PConfig
		TorListen map[string]*TorConfig
	}
	Operator    map[string]*PassConfig
	Account     map[string]*PassConfig
	TemplateDir string
}

func (conf *Config) Operators() map[Name][]byte {
	operators := make(map[Name][]byte)
	for name, opConf := range conf.Operator {
		operators[NewName(name)] = opConf.PasswordBytes()
	}
	return operators
}

func (conf *Config) Accounts() map[string][]byte {
	accounts := make(map[string][]byte)
	for name, account := range conf.Account {
		accounts[name] = []byte(account.Password)
	}
	return accounts
}

func (conf *Config) Name() string {
	return conf.filename
}

func (conf *Config) Reload() error {
	conf.Lock()
	defer conf.Unlock()

	newconf, err := LoadConfig(conf.filename)
	if err != nil {
		return nil
	}

	err = mergo.MergeWithOverwrite(conf, newconf)
	if err != nil {
		return nil
	}

	return nil
}

func LoadConfig(filename string) (config *Config, err error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	config.filename = filename

	if config.Network.Name == "" {
		return nil, errors.New("Network name missing")
	}

	if config.Server.Name == "" {
		return nil, errors.New("Server name missing")
	}

	if !IsHostname(config.Server.Name) {
		return nil, errors.New("Server name must match the format of a hostname")
	}

	if len(config.Server.Listen)+len(config.Server.TLSListen)+len(config.Server.I2PListen)+len(config.Server.TorListen) == 0 {
		return nil, errors.New("Server listening addresses missing")
	}

	return config, nil
}

func (config *Config) WWWAddrs() string {
	s := ""
	for _, addr := range config.WWW.Listen {
		s += addr + "\n"
	}
	return s
}
func (config *Config) TLSWWWAddrs() string {
	s := ""
	for addr := range config.WWW.TLSListen {
		s += addr + "\n"
	}
	return s
}
func (config *Config) I2PWWWAddrs() string {
	s := ""
	for addr, i2pconfig := range config.WWW.I2PListen {
		s += addr + ": " + i2pconfig.Base32 + "\n"
	}
	return s
}
func (config *Config) TorWWWAddrs() string {
	s := ""
	for addr, torconfig := range config.WWW.TorListen {
		s += addr + ": " + torconfig.Onion + "\n"
	}
	return s
}

func (config *Config) IRCAddrs() string {
	s := ""
	for _, addr := range config.Server.Listen {
		s += addr + "\n"
	}
	return s
}
func (config *Config) TLSIRCAddrs() string {
	s := ""
	for addr := range config.Server.TLSListen {
		s += addr + "\n"
	}
	return s
}
func (config *Config) I2PIRCAddrs() string {
	s := ""
	for addr, i2pconfig := range config.Server.I2PListen {
		s += addr + ": " + i2pconfig.Base32 + "\n"
	}
	return s
}
func (config *Config) TorIRCAddrs() string {
	s := ""
	for addr, torconfig := range config.Server.TorListen {
		s += addr + ": " + torconfig.Onion + "\n"
	}
	return s
}
