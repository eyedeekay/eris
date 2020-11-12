package irc

import (
	//	"fmt"
	log "github.com/sirupsen/logrus"
	"html/template"
	"net/http"
	"strings"
)

var network_template string = `<html>
<head>
</head>
<body>
  <style>
  body {
    font-family: monospace;
    font-size: large;
  }
  b   {
    color: black;
  }
  p    {
    color: darkgrey;
  }
  </style>
  <h1>Network: {{ .Network.Name }}</h1>
  <div>This is a web page intended to help your IRC users get the information
they need to connect to your IRC network. It lists all your IRC server's addresses
around the world.</div>
`

var server_template string = `
  <div>
    <h2>IRC Server Information</h2>
    <ul>
      <li><b>IRC Addresses: </b>{{ .IRCAddrs }}</li>
      <li><b>TLS IRC Addresses: </b>{{ .TLSIRCAddrs }}</li>
      <li><b>IRC I2P Addresses: </b>{{ .I2PIRCAddrs }}</li>
      <li><b>IRC Tor Addresses: </b>{{ .TorIRCAddrs }}</li>
      <li><b>Name: </b><span>{{ .Server.Name }}</span></li>
      <li><b>Description: </b><span>{{ .Server.Description }}</span></li>
    </ul>
  </div>
`

var ops_template string = `
  <div>
    <h2>Web Server Information</h2>
    <ul>
      <li><b>Help Page Addresses on the Web: </b>{{ .WWWAddrs }}</li>
      <li><b>TLS Addresses on the Web(HTTPS): </b>{{ .TLSWWWAddrs }}</li>
      <li><b>Web Addresses on I2P: </b>{{ .I2PWWWAddrs }}</li>
      <li><b>Web Addresses on Tor: </b>{{ .TorWWWAddrs }}</li>
    </ul>
  </div>
</body>
`

var default_template string = network_template + server_template + ops_template

func (server *Server) ServeHTTP(rw http.ResponseWriter, rq *http.Request) {

	rw.Header().Add("Content-Type", "text/html")
	tmp := strings.Split(rq.URL.Path, "/")
	lang := "en"
	if len(tmp) > 1 {
		cleaned := strings.Replace(tmp[1], "/", "", -1)
		if cleaned == "" {
			lang = "en"
		} else {
			lang = cleaned
		}
	}
	log.Infof("Rendering language: %d %s, %s", len(tmp), lang, server.templates[lang])
	tmpl, err := template.New(server.config.Network.Name).Parse(server.templates[lang])
	if err != nil {
		log.Fatalf("Template generation error, %s", err)
	}
	err = tmpl.Execute(rw, server.config)
	if err != nil {
		log.Fatalf("Template execution error, %s", err)
	}
}
