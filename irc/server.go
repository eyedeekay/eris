package irc

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/eyedeekay/sam3"
	"github.com/eyedeekay/sam3/i2pkeys"
	log "github.com/sirupsen/logrus"
)

type ServerCommand interface {
	Command
	HandleServer(*Server)
}

type RegServerCommand interface {
	Command
	HandleRegServer(*Server)
}

type Server struct {
	config      *Config
	metrics     *Metrics
	channels    *ChannelNameMap
	connections *Counter
	clients     *ClientLookupSet
	ctime       time.Time
	idle        chan *Client
	motdFile    string
	name        Name
	network     Name
	description string
	newConns    chan net.Conn
	operators   map[Name][]byte
	accounts    PasswordStore
	password    []byte
	signals     chan os.Signal
	done        chan bool
	whoWas      *WhoWasList
	ids         map[string]*Identity
}

var (
	SERVER_SIGNALS = []os.Signal{
		syscall.SIGINT,
		syscall.SIGTERM,
	}
)

func NewServer(config *Config) *Server {
	server := &Server{
		config:      config,
		metrics:     NewMetrics("eris"),
		channels:    NewChannelNameMap(),
		connections: &Counter{},
		clients:     NewClientLookupSet(),
		ctime:       time.Now(),
		idle:        make(chan *Client),
		motdFile:    config.Server.MOTD,
		name:        NewName(config.Server.Name),
		network:     NewName(config.Network.Name),
		description: config.Server.Description,
		newConns:    make(chan net.Conn),
		operators:   config.Operators(),
		accounts:    NewMemoryPasswordStore(config.Accounts(), PasswordStoreOpts{}),
		signals:     make(chan os.Signal, len(SERVER_SIGNALS)),
		done:        make(chan bool),
		whoWas:      NewWhoWasList(100),
		ids:         make(map[string]*Identity),
	}

	log.Debugf("accounts: %v", config.Accounts())

	// TODO: Make this configureable?
	server.ids["global"] = NewIdentity(config.Server.Name, "global")

	if config.Server.Password != "" {
		server.password = config.Server.PasswordBytes()
	}

	for _, addr := range config.Server.Listen {
		server.listen(addr)
	}

	for addr, tlsconfig := range config.Server.TLSListen {
		server.listentls(addr, tlsconfig)
	}

	for addr, i2pconfig := range config.Server.I2PListen {
		server.listeni2p(addr, i2pconfig)
		err := config.StoreConfig()
		if err != nil {
			log.Fatalf("error storing I2P base32 address in config")
		}
	}

	signal.Notify(server.signals, SERVER_SIGNALS...)

	// server uptime counter
	server.metrics.NewCounterFunc(
		"server", "uptime",
		"Number of seconds the server has been running",
		func() float64 {
			return float64(time.Since(server.ctime).Nanoseconds())
		},
	)

	// client commands counter
	server.metrics.NewCounter(
		"client", "commands",
		"Number of client commands processed",
	)

	// client messages counter
	server.metrics.NewCounter(
		"client", "messages",
		"Number of client messages exchanged",
	)

	// server connections gauge
	server.metrics.NewGaugeFunc(
		"server", "connections",
		"Number of active connections to the server",
		func() float64 {
			return float64(server.connections.Value())
		},
	)

	// server registered (clients) gauge
	server.metrics.NewGaugeFunc(
		"server", "registered",
		"Number of registered clients connected",
		func() float64 {
			return float64(server.clients.Count())
		},
	)

	// server clients gauge (by secure/insecure)
	server.metrics.NewGaugeVec(
		"server", "clients",
		"Number of registered clients connected (by secure/insecure)",
		[]string{"secure"},
	)

	// server channels gauge
	server.metrics.NewGaugeFunc(
		"server", "channels",
		"Number of active channels",
		func() float64 {
			return float64(server.channels.Count())
		},
	)

	// client command processing time summaries
	server.metrics.NewSummaryVec(
		"client", "command_duration_seconds",
		"Client command processing time in seconds",
		[]string{"command"},
	)

	// client ping latency summary
	server.metrics.NewSummary(
		"client", "ping_latency_seconds",
		"Client ping latency in seconds",
	)

	go server.metrics.Run(":9314")

	return server
}

func (server *Server) Wallops(message string) {
	text := NewText(message)
	server.clients.Range(func(_ Name, client *Client) bool {
		if client.modes.Has(WallOps) {
			server.metrics.Counter("client", "messages").Inc()
			client.replies <- RplNotice(server, client, text)
		}
		return true
	})
}

func (server *Server) Wallopsf(format string, args ...interface{}) {
	server.Wallops(fmt.Sprintf(format, args...))
}

func (server *Server) Global(message string) {
	text := NewText(message)
	server.clients.Range(func(_ Name, client *Client) bool {
		server.metrics.Counter("client", "messages").Inc()
		client.replies <- RplNotice(server.ids["global"], client, text)
		return true
	})
}

func (server *Server) Globalf(format string, args ...interface{}) {
	server.Global(fmt.Sprintf(format, args...))
}

func (server *Server) Shutdown() {
	server.Global("shutting down...")
}

func (server *Server) Stop() {
	server.done <- true
}

func (server *Server) Run() {
	for {
		select {
		case <-server.done:
			return
		case <-server.signals:
			server.Shutdown()
			// Give at least 1s for clients to see the shutdown
			go func() {
				time.Sleep(1 * time.Second)
				server.Stop()
			}()

		case conn := <-server.newConns:
			go NewClient(server, conn)

		case client := <-server.idle:
			client.Idle()
		}
	}
}

func (s *Server) acceptor(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Errorf("%s accept error: %s", s, err)
			continue
		}
		log.Debugf("%s accept: %s", s, conn.RemoteAddr())

		if _, ok := conn.(*tls.Conn); ok {
			s.metrics.GaugeVec("server", "clients").WithLabelValues("secure").Inc()
		} else {
			s.metrics.GaugeVec("server", "clients").WithLabelValues("insecure").Inc()
		}

		s.connections.Inc()
		s.newConns <- conn
	}
}

//
// listen goroutine
//

func (s *Server) listen(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(s, "listen error: ", err)
	}

	log.Infof("%s listening on %s", s, addr)

	go s.acceptor(listener)
}

//
// listen tls goroutine
//

func (s *Server) listentls(addr string, tlsconfig *TLSConfig) {
	cert, err := tls.LoadX509KeyPair(tlsconfig.Cert, tlsconfig.Key)
	if err != nil {
		log.Fatalf("error loading tls cert/key pair: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader
	listener, err := tls.Listen("tcp", addr, &config)
	if err != nil {
		log.Fatalf("error binding to %s: %s", addr, err)
	}

	log.Infof("%s listening on %s (TLS)", s, addr)

	go s.acceptor(listener)
}

//
// listen i2p goroutine
//

func (s *Server) listeni2p(addr string, i2pconfig *I2PConfig) {
	sam, err := sam3.NewSAM(i2pconfig.SAMaddr)
	if err != nil {
		log.Fatalf("error connecting to SAM to %s: %s", addr, err)
	}
	var keys *i2pkeys.I2PKeys
	if _, err := os.Stat(i2pconfig.I2Pkeys); os.IsNotExist(err) {
		f, err := os.Create(i2pconfig.I2Pkeys)
		if err != nil {
			log.Fatalf("Keyfile creation error: %s", err)
		}
		defer f.Close()
		if err != nil {
			log.Infof("Key loading error: %e", err)
		}
		tkeys, err := sam.NewKeys()
		if err != nil {
			log.Fatalf("Unable to load or generate I2P Keys, %s", err)
		}
		keys = &tkeys
		err = i2pkeys.StoreKeysIncompat(*keys, f)
		if err != nil {
			log.Fatalf("Unable to save newly generated I2P Keys, %s", err)
		}
		i2pconfig.Base32 = keys.Addr().Base32()
	} else {
		tkeys, err := i2pkeys.LoadKeys(i2pconfig.I2Pkeys)
		if err != nil {
			log.Infof("Key loading error: %e", err)
		}
		keys = &tkeys
	}
	// If the keys and the base32 are different, keys win.
	i2pconfig.Base32 = keys.Addr().Base32()

	if err != nil {
		log.Fatalf("error generating I2P keys %s: %s", addr, err)
	}
	stream, err := sam.NewStreamSession(addr, *keys, sam3.Options_Medium)
	if err != nil {
		log.Fatalf("error creating streaming connection %s: %s, %s.", addr, err, *keys)
	}
	listener, err := stream.Listen()
	if err != nil {
		log.Fatalf("error binding to %s: %s", keys.Addr().Base32(), err)
	}
	go s.acceptor(listener)
}

//
// server functionality
//

func (s *Server) tryRegister(c *Client) {
	if c.registered || !c.HasNick() || !c.HasUsername() ||
		(c.capState == CapNegotiating) {
		return
	}

	c.Register()
	c.RplWelcome()
	c.RplYourHost()
	c.RplCreated()
	c.RplMyInfo()

	lusers := LUsersCommand{}
	lusers.SetClient(c)
	lusers.HandleServer(s)

	s.MOTD(c)
}

func (server *Server) MOTD(client *Client) {
	if server.motdFile == "" {
		client.ErrNoMOTD()
		return
	}

	file, err := os.Open(server.motdFile)
	if err != nil {
		client.ErrNoMOTD()
		return
	}
	defer file.Close()

	client.RplMOTDStart()
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")

		client.RplMOTD(line)
	}
	client.RplMOTDEnd()
}

func (s *Server) Rehash() error {
	err := s.config.Reload()
	if err != nil {
		return err
	}

	s.motdFile = s.config.Server.MOTD
	s.name = NewName(s.config.Server.Name)
	s.network = NewName(s.config.Network.Name)
	s.description = s.config.Server.Description
	s.operators = s.config.Operators()

	return nil
}

func (s *Server) Id() Name {
	return s.name
}

func (s *Server) Network() Name {
	return s.network
}

func (s *Server) String() string {
	return s.name.String()
}

func (s *Server) Nick() Name {
	return s.Id()
}

func (server *Server) Reply(target *Client, message string) {
	target.Reply(RplPrivMsg(server, target, NewText(message)))
}

func (server *Server) Replyf(target *Client, format string, args ...interface{}) {
	server.Reply(target, fmt.Sprintf(format, args...))
}

//
// registration commands
//

func (msg *PassCommand) HandleRegServer(server *Server) {
	client := msg.Client()
	if msg.err != nil {
		client.ErrPasswdMismatch()
		client.Quit("bad password")
		return
	}

	client.authorized = true
}

func (msg *RFC1459UserCommand) HandleRegServer(server *Server) {
	client := msg.Client()
	if !client.authorized {
		client.ErrPasswdMismatch()
		client.Quit("bad password")
		return
	}
	msg.setUserInfo(server)
}

func (msg *RFC2812UserCommand) HandleRegServer(server *Server) {
	client := msg.Client()
	if !client.authorized {
		client.ErrPasswdMismatch()
		client.Quit("bad password")
		return
	}
	flags := msg.Flags()
	if len(flags) > 0 {
		for _, mode := range flags {
			client.modes.Set(mode)
		}
		client.RplUModeIs(client)
	}
	msg.setUserInfo(server)
}

func (msg *AuthenticateCommand) HandleRegServer(server *Server) {
	client := msg.Client()
	if !client.authorized {
		client.ErrPasswdMismatch()
		client.Quit("bad password")
		return
	}

	if msg.arg == "*" {
		client.ErrSaslAborted()
		return
	}

	if !client.sasl.Started() {
		if msg.arg == "PLAIN" {
			client.sasl.Start()
			client.Reply(RplAuthenticate(client, "+"))
		} else {
			client.RplSaslMechs("PLAIN")
			client.ErrSaslFail("Unknown authentication mechanism")
		}
		return
	}

	if len(msg.arg) > 400 {
		client.ErrSaslTooLong()
		return
	}

	if len(msg.arg) == 400 {
		client.sasl.WriteString(msg.arg)
		return
	}

	if msg.arg != "+" {
		client.sasl.WriteString(msg.arg)
	}

	data, err := base64.StdEncoding.DecodeString(client.sasl.String())
	if err != nil {
		client.ErrSaslFail("Invalid base64 encoding")
		client.sasl.Reset()
		return
	}

	// Do authentication

	var (
		authcid  string
		authzid  string
		password string
	)

	tokens := bytes.Split(data, []byte{'\000'})
	if len(tokens) == 3 {
		authcid = string(tokens[0])
		authzid = string(tokens[1])
		password = string(tokens[2])

		if authzid == "" {
			authzid = authcid
		} else if authzid != authcid {
			client.ErrSaslFail("authzid and authcid should be the same")
			return
		}
	} else {
		client.ErrSaslFail("invalid authentication blob")
		return
	}

	err = server.accounts.Verify(authcid, password)
	if err != nil {
		client.ErrSaslFail("invalid authentication")
		return
	}

	client.sasl.Login(authcid)
	client.RplLoggedIn(authcid)
	client.RplSaslSuccess()

	client.modes.Set(Registered)
	client.Reply(
		RplModeChanges(
			client, client,
			ModeChanges{
				&ModeChange{mode: Registered, op: Add},
			},
		),
	)
}

func (msg *UserCommand) setUserInfo(server *Server) {
	client := msg.Client()

	server.clients.Remove(client)
	client.username, client.realname = msg.username, msg.realname
	server.clients.Add(client)

	server.tryRegister(client)
}

func (msg *QuitCommand) HandleRegServer(server *Server) {
	msg.Client().Quit(msg.message)
}

//
// normal commands
//

func (m *PassCommand) HandleServer(s *Server) {
	m.Client().ErrAlreadyRegistered()
}

func (m *PingCommand) HandleServer(s *Server) {
	client := m.Client()
	client.Reply(RplPong(client, m.server.Text()))
}

func (m *PongCommand) HandleServer(s *Server) {
	v := s.metrics.Summary("client", "ping_latency_seconds")
	v.Observe(time.Now().Sub(m.Client().pingTime).Seconds())
}

func (m *UserCommand) HandleServer(s *Server) {
	m.Client().ErrAlreadyRegistered()
}

func (msg *QuitCommand) HandleServer(server *Server) {
	msg.Client().Quit(msg.message)
}

func (m *JoinCommand) HandleServer(s *Server) {
	client := m.Client()

	if m.zero {
		client.channels.Range(func(channel *Channel) bool {
			channel.Part(client, client.Nick().Text())
			return true
		})
		return
	}

	for name, key := range m.channels {
		if !name.IsChannel() {
			client.ErrNoSuchChannel(name)
			continue
		}

		channel := s.channels.Get(name)
		if channel == nil {
			channel = NewChannel(s, name, true)
		}
		channel.Join(client, key)
	}
}

func (m *PartCommand) HandleServer(server *Server) {
	client := m.Client()
	for _, chname := range m.channels {
		channel := server.channels.Get(chname)

		if channel == nil {
			m.Client().ErrNoSuchChannel(chname)
			continue
		}

		channel.Part(client, m.Message())
	}
}

func (msg *TopicCommand) HandleServer(server *Server) {
	client := msg.Client()
	channel := server.channels.Get(msg.channel)
	if channel == nil {
		client.ErrNoSuchChannel(msg.channel)
		return
	}

	if msg.setTopic {
		channel.SetTopic(client, msg.topic)
	} else {
		channel.GetTopic(client)
	}
}

func (msg *PrivMsgCommand) HandleServer(server *Server) {
	client := msg.Client()
	if msg.target.IsChannel() {
		channel := server.channels.Get(msg.target)
		if channel == nil {
			client.ErrNoSuchChannel(msg.target)
			return
		}

		channel.PrivMsg(client, msg.message)
		return
	}

	target := server.clients.Get(msg.target)
	if target == nil {
		client.ErrNoSuchNick(msg.target)
		return
	}
	if !client.CanSpeak(target) {
		client.ErrCannotSendToUser(target.nick, "secure connection required")
		return
	}
	server.metrics.Counter("client", "messages").Inc()
	target.Reply(RplPrivMsg(client, target, msg.message))
	if target.modes.Has(Away) {
		client.RplAway(target)
	}
}

func (client *Client) WhoisChannelsNames(target *Client) []string {
	chstrs := make([]string, client.channels.Count())
	index := 0
	client.channels.Range(func(channel *Channel) bool {
		if !CanSeeChannel(target, channel) {
			return true
		}

		switch {
		case channel.members.Get(client).Has(ChannelOperator):
			chstrs[index] = "@" + channel.name.String()

		case channel.members.Get(client).Has(Voice):
			chstrs[index] = "+" + channel.name.String()

		default:
			chstrs[index] = channel.name.String()
		}
		index++
		return true
	})
	return chstrs
}

func (m *WhoisCommand) HandleServer(server *Server) {
	client := m.Client()

	// TODO implement target query

	for _, mask := range m.masks {
		matches := server.clients.FindAll(mask)
		if matches.Count() == 0 {
			client.ErrNoSuchNick(mask)
			continue
		}
		matches.Range(func(mclient *Client) bool {
			client.RplWhois(mclient)
			return true
		})
	}
}

func whoChannel(client *Client, channel *Channel, friends *ClientSet) {
	channel.members.Range(func(member *Client, _ *ChannelModeSet) bool {
		if !client.modes.Has(Invisible) || friends.Has(client) {
			client.RplWhoReply(channel, member)
		}
		return true
	})
}

func (msg *WhoCommand) HandleServer(server *Server) {
	client := msg.Client()
	friends := client.Friends()
	mask := msg.mask

	if mask == "" {
		server.channels.Range(func(name Name, channel *Channel) bool {
			whoChannel(client, channel, friends)
			return true
		})
	} else if mask.IsChannel() {
		// TODO implement wildcard matching
		channel := server.channels.Get(mask)
		if channel != nil {
			whoChannel(client, channel, friends)
		}
	} else {
		matches := server.clients.FindAll(mask)
		matches.Range(func(mclient *Client) bool {
			client.RplWhoReply(nil, mclient)
			return true
		})
	}

	client.RplEndOfWho(mask)
}

func (msg *OperCommand) HandleServer(server *Server) {
	client := msg.Client()

	if (msg.hash == nil) || (msg.err != nil) {
		client.ErrPasswdMismatch()
		return
	}

	client.modes.Set(Operator)
	client.modes.Set(WallOps)
	client.RplYoureOper()
	client.Reply(
		RplModeChanges(
			client, client,
			ModeChanges{
				&ModeChange{mode: Operator, op: Add},
				&ModeChange{mode: WallOps, op: Add},
			},
		),
	)
}

func (msg *RehashCommand) HandleServer(server *Server) {
	client := msg.Client()
	if !client.modes.Has(Operator) {
		client.ErrNoPrivileges()
		return
	}

	server.Wallopsf(
		"Rehashing server config (%s)",
		client.Nick(),
	)

	err := server.Rehash()
	if err != nil {
		server.Wallopsf(
			"ERROR: Rehashing config failed (%s)",
			err,
		)
		return
	}

	client.RplRehashing()
}

func (msg *AwayCommand) HandleServer(server *Server) {
	client := msg.Client()
	if len(msg.text) > 0 {
		client.modes.Set(Away)
	} else {
		client.modes.Unset(Away)
	}
	client.awayMessage = msg.text
}

func (msg *IsOnCommand) HandleServer(server *Server) {
	client := msg.Client()

	ison := make([]string, 0)
	for _, nick := range msg.nicks {
		if iclient := server.clients.Get(nick); iclient != nil {
			ison = append(ison, iclient.Nick().String())
		}
	}

	client.RplIsOn(ison)
}

func (msg *MOTDCommand) HandleServer(server *Server) {
	server.MOTD(msg.Client())
}

func (msg *NoticeCommand) HandleServer(server *Server) {
	client := msg.Client()

	if msg.target == "*" && client.modes.Has(Operator) {
		server.Global(msg.message.String())
		return
	}

	if msg.target.IsChannel() {
		channel := server.channels.Get(msg.target)
		if channel == nil {
			client.ErrNoSuchChannel(msg.target)
			return
		}

		channel.Notice(client, msg.message)
		return
	}

	target := server.clients.Get(msg.target)
	if target == nil {
		client.ErrNoSuchNick(msg.target)
		return
	}

	if !client.CanSpeak(target) {
		client.ErrCannotSendToUser(target.nick, "secure connection required")
		return
	}
	server.metrics.Counter("client", "messages").Inc()
	target.Reply(RplNotice(client, target, msg.message))
}

func (msg *KickCommand) HandleServer(server *Server) {
	client := msg.Client()
	for chname, nickname := range msg.kicks {
		channel := server.channels.Get(chname)
		if channel == nil {
			client.ErrNoSuchChannel(chname)
			continue
		}

		target := server.clients.Get(nickname)
		if target == nil {
			client.ErrNoSuchNick(nickname)
			continue
		}

		channel.Kick(client, target, msg.Comment())
	}
}

func (msg *ListCommand) HandleServer(server *Server) {
	client := msg.Client()

	// TODO target server
	if msg.target != "" {
		client.ErrNoSuchServer(msg.target)
		return
	}

	if len(msg.channels) == 0 {
		server.channels.Range(func(name Name, channel *Channel) bool {
			if !CanSeeChannel(client, channel) {
				return true
			}
			client.RplList(channel)
			return true
		})
	} else {
		for _, chname := range msg.channels {
			channel := server.channels.Get(chname)
			if channel == nil || !CanSeeChannel(client, channel) {
				client.ErrNoSuchChannel(chname)
				continue
			}
			client.RplList(channel)
		}
	}
	client.RplListEnd(server)
}

func (msg *NamesCommand) HandleServer(server *Server) {
	client := msg.Client()
	if server.channels.Count() == 0 {
		server.channels.Range(func(name Name, channel *Channel) bool {
			channel.Names(client)
			return true
		})
		return
	}

	for _, chname := range msg.channels {
		channel := server.channels.Get(chname)
		if channel == nil {
			client.ErrNoSuchChannel(chname)
			continue
		}
		channel.Names(client)
	}
}

func (msg *VersionCommand) HandleServer(server *Server) {
	client := msg.Client()
	if (msg.target != "") && (msg.target != server.name) {
		client.ErrNoSuchServer(msg.target)
		return
	}

	client.RplVersion()
}

func (msg *InviteCommand) HandleServer(server *Server) {
	client := msg.Client()

	target := server.clients.Get(msg.nickname)
	if target == nil {
		client.ErrNoSuchNick(msg.nickname)
		return
	}

	channel := server.channels.Get(msg.channel)
	if channel == nil {
		client.RplInviting(target, msg.channel)
		target.Reply(RplInviteMsg(client, target, msg.channel))
		return
	}

	channel.Invite(target, client)
}

func (msg *TimeCommand) HandleServer(server *Server) {
	client := msg.Client()
	if (msg.target != "") && (msg.target != server.name) {
		client.ErrNoSuchServer(msg.target)
		return
	}
	client.RplTime()
}

func (msg *LUsersCommand) HandleServer(server *Server) {
	client := msg.Client()

	client.RplLUserClient()
	client.RplLUserOp()
	client.RplLUserUnknown()
	client.RplLUserChannels()
	client.RplLUserMe()
}

func (msg *WallopsCommand) HandleServer(server *Server) {
	client := msg.Client()
	if !client.modes.Has(Operator) {
		client.ErrNoPrivileges()
		return
	}

	server.Wallops(msg.message.String())
}

func (msg *KillCommand) HandleServer(server *Server) {
	client := msg.Client()
	if !client.modes.Has(Operator) {
		client.ErrNoPrivileges()
		return
	}

	target := server.clients.Get(msg.nickname)
	if target == nil {
		client.ErrNoSuchNick(msg.nickname)
		return
	}

	quitMsg := fmt.Sprintf("KILLed by %s: %s", client.Nick(), msg.comment)
	target.Quit(NewText(quitMsg))
}

func (msg *WhoWasCommand) HandleServer(server *Server) {
	client := msg.Client()
	for _, nickname := range msg.nicknames {
		results := server.whoWas.Find(nickname, msg.count)
		if len(results) == 0 {
			client.ErrWasNoSuchNick(nickname)
		} else {
			for _, whoWas := range results {
				client.RplWhoWasUser(whoWas)
			}
		}
		client.RplEndOfWhoWas(nickname)
	}
}
