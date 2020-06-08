package irc

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	IDLE_TIMEOUT = time.Minute // how long before a client is considered idle
	QUIT_TIMEOUT = time.Minute // how long after idle before a client is kicked
)

type SyncBool struct {
	sync.RWMutex

	value bool
}

func NewSyncBool(value bool) *SyncBool {
	return &SyncBool{value: value}
}

func (sb *SyncBool) Get() bool {
	sb.RLock()
	defer sb.RUnlock()

	return sb.value
}

func (sb *SyncBool) Set(value bool) {
	sb.Lock()
	defer sb.Unlock()

	sb.value = value
}

type Client struct {
	atime        time.Time
	authorized   bool
	awayMessage  Text
	capabilities CapabilitySet
	capState     CapState
	channels     *ChannelSet
	ctime        time.Time
	modes        *UserModeSet
	hasQuit      *SyncBool
	hops         uint
	hostname     Name
	hostmask     Name // Cloacked hostname (SHA256)
	pingTime     time.Time
	idleTimer    *time.Timer
	nick         Name
	quitTimer    *time.Timer
	realname     Text
	registered   bool
	sasl         *SaslState
	server       *Server
	socket       *Socket
	replies      chan string
	username     Name
}

func NewClient(server *Server, conn net.Conn) *Client {
	now := time.Now()
	c := &Client{
		atime:        now,
		authorized:   len(server.password) == 0,
		capState:     CapNone,
		capabilities: make(CapabilitySet),
		channels:     NewChannelSet(),
		ctime:        now,
		modes:        NewUserModeSet(),
		hasQuit:      NewSyncBool(false),
		sasl:         NewSaslState(),
		server:       server,
		socket:       NewSocket(conn),
		replies:      make(chan string),
	}

	if _, ok := conn.(*tls.Conn); ok {
		c.modes.Set(SecureConn)
	}

	c.Touch()
	go c.writeloop()
	go c.readloop()

	return c
}

//
// command goroutine
//

func (c *Client) writeloop() {
	for {
		select {
		case reply, ok := <-c.replies:
			if !ok || reply == "" || c.socket == nil {
				return
			}
			c.socket.Write(reply)
		}
	}
}

func (c *Client) readloop() {
	var command Command
	var err error
	var line string

	// Set the hostname for this client.
	c.hostname = AddrLookupHostname(c.socket.conn.RemoteAddr())
	c.hostmask = NewName(SHA256(c.hostname.String()))

	for err == nil {
		if line, err = c.socket.Read(); err != nil {
			command = NewQuitCommand("connection closed")

		} else if command, err = ParseCommand(line); err != nil {
			switch err {
			case ErrParseCommand:
				//TODO(dan): use the real failed numeric for this (400)
				c.Reply(RplNotice(c.server, c, NewText("failed to parse command")))

			case NotEnoughArgsError:
				// TODO
			}
			// so the read loop will continue
			err = nil
			continue

		} else if checkPass, ok := command.(checkPasswordCommand); ok {
			checkPass.LoadPassword(c.server)
			// Block the client thread while handling a potentially expensive
			// password bcrypt operation. Since the server is single-threaded
			// for commands, we don't want the server to perform the bcrypt,
			// blocking anyone else from sending commands until it
			// completes. This could be a form of DoS if handled naively.
			checkPass.CheckPassword()
		}

		c.processCommand(command)
	}
}

func (c *Client) processCommand(cmd Command) {
	cmd.SetClient(c)

	if !c.registered {
		regCmd, ok := cmd.(RegServerCommand)
		if !ok {
			c.Quit("unexpected command")
			return
		}
		regCmd.HandleRegServer(c.server)
		return
	}

	srvCmd, ok := cmd.(ServerCommand)
	if !ok {
		c.ErrUnknownCommand(cmd.Code())
		return
	}

	c.server.metrics.Counter("client", "commands").Inc()

	defer func(t time.Time) {
		v := c.server.metrics.SummaryVec("client", "command_duration_seconds")
		v.WithLabelValues(cmd.Code().String()).Observe(time.Now().Sub(t).Seconds())
	}(time.Now())

	switch srvCmd.(type) {
	case *PingCommand, *PongCommand:
		c.Touch()

	case *QuitCommand:
		// no-op

	default:
		c.Active()
		c.Touch()
	}

	srvCmd.HandleServer(c.server)
}

// quit timer goroutine

func (c *Client) connectionTimeout() {
	c.processCommand(NewQuitCommand("connection timeout"))
}

//
// idle timer goroutine
//

func (c *Client) connectionIdle() {
	c.server.idle <- c
}

//
// server goroutine
//

func (c *Client) Active() {
	c.atime = time.Now()
}

func (c *Client) Touch() {
	if c.quitTimer != nil {
		c.quitTimer.Stop()
	}

	if c.idleTimer == nil {
		c.idleTimer = time.AfterFunc(IDLE_TIMEOUT, c.connectionIdle)
	} else {
		c.idleTimer.Reset(IDLE_TIMEOUT)
	}
}

func (c *Client) Idle() {
	c.pingTime = time.Now()
	c.Reply(RplPing(c.server))

	if c.quitTimer == nil {
		c.quitTimer = time.AfterFunc(QUIT_TIMEOUT, c.connectionTimeout)
	} else {
		c.quitTimer.Reset(QUIT_TIMEOUT)
	}
}

func (c *Client) Register() {
	if c.registered {
		return
	}
	c.registered = true
	c.modes.Set(HostMask)
	c.Touch()
}

func (c *Client) destroy() {
	// clean up channels

	c.channels.Range(func(channel *Channel) bool {
		channel.Quit(c)
		return true
	})

	// clean up server

	if _, ok := c.socket.conn.(*tls.Conn); ok {
		c.server.metrics.GaugeVec("server", "clients").WithLabelValues("secure").Dec()
	} else {
		c.server.metrics.GaugeVec("server", "clients").WithLabelValues("insecure").Dec()
	}

	c.server.connections.Dec()
	c.server.clients.Remove(c)

	// clean up self

	if c.idleTimer != nil {
		c.idleTimer.Stop()
	}
	if c.quitTimer != nil {
		c.quitTimer.Stop()
	}

	close(c.replies)

	c.socket.Close()

	log.Debugf("%s: destroyed", c)
}

func (c *Client) IdleTime() time.Duration {
	return time.Since(c.atime)
}

func (c *Client) SignonTime() int64 {
	return c.ctime.Unix()
}

func (c *Client) IdleSeconds() uint64 {
	return uint64(c.IdleTime().Seconds())
}

func (c *Client) HasNick() bool {
	return c.nick != ""
}

func (c *Client) HasUsername() bool {
	return c.username != ""
}

func (c *Client) CanSpeak(target *Client) bool {
	requiresSecure := c.modes.Has(SecureOnly) || target.modes.Has(SecureOnly)
	isSecure := c.modes.Has(SecureConn) && target.modes.Has(SecureConn)
	isOperator := c.modes.Has(Operator)

	return !requiresSecure || (requiresSecure && (isOperator || isSecure))
}

// <mode>
func (c *Client) ModeString() (str string) {
	return c.modes.String()
}

func (c *Client) UserHost(cloacked bool) Name {
	username := "*"
	if c.username != "" {
		username = c.username.String()
	}
	if cloacked {
		return Name(fmt.Sprintf("%s!%s@%s", c.nick, username, c.hostmask))
	}
	return Name(fmt.Sprintf("%s!%s@%s", c.nick, username, c.hostname))
}

func (c *Client) Server() Name {
	return c.server.name
}

func (c *Client) ServerInfo() string {
	return c.server.description
}

func (c *Client) Nick() Name {
	if c.HasNick() {
		return c.nick
	}
	return Name("*")
}

func (c *Client) Id() Name {
	return c.UserHost(true)
}

func (c *Client) String() string {
	return c.Id().String()
}

func (c *Client) Friends() *ClientSet {
	friends := NewClientSet()
	friends.Add(c)
	c.channels.Range(func(channel *Channel) bool {
		channel.members.Range(func(member *Client, _ *ChannelModeSet) bool {
			friends.Add(member)
			return true
		})
		return true
	})
	return friends
}

func (c *Client) SetNickname(nickname Name) {
	if c.nick != "" {
		log.Errorf("%s nickname already set!", c)
		return
	}
	c.nick = nickname
	c.server.clients.Add(c)
}

func (c *Client) ChangeNickname(nickname Name) {
	// Make reply before changing nick to capture original source id.
	reply := RplNick(c, nickname)
	c.server.clients.Remove(c)
	c.server.whoWas.Append(c)
	c.nick = nickname
	c.server.clients.Add(c)
	c.Friends().Range(func(friend *Client) bool {
		friend.Reply(reply)
		return true
	})
}

func (c *Client) Reply(reply string) {
	if !c.hasQuit.Get() {
		c.replies <- reply
	}
}

func (c *Client) Quit(message Text) {
	if c.hasQuit.Get() {
		return
	}

	c.hasQuit.Set(true)
	c.Reply(RplError("quit"))
	c.server.whoWas.Append(c)
	friends := c.Friends()
	friends.Remove(c)
	c.destroy()

	if friends.Count() > 0 {
		reply := RplQuit(c, message)
		friends.Range(func(friend *Client) bool {
			friend.Reply(reply)
			return true
		})
	}
}
