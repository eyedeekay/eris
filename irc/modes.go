package irc

import (
	"strings"
)

// user mode flags
type UserMode rune

func (mode UserMode) String() string {
	return string(mode)
}

type UserModes []UserMode

func (modes UserModes) String() string {
	strs := make([]string, len(modes))
	for index, mode := range modes {
		strs[index] = mode.String()
	}
	return strings.Join(strs, "")
}

// channel mode flags
type ChannelMode rune

func (mode ChannelMode) String() string {
	return string(mode)
}

type ChannelModes []ChannelMode

func (modes ChannelModes) String() string {
	strs := make([]string, len(modes))
	for index, mode := range modes {
		strs[index] = mode.String()
	}
	return strings.Join(strs, "")
}

type ModeOp rune

func (op ModeOp) String() string {
	return string(op)
}

const (
	Add    ModeOp = '+'
	List   ModeOp = '='
	Remove ModeOp = '-'
)

const (
	Away       UserMode = 'a' // not a real user mode (flag)
	Invisible  UserMode = 'i'
	Operator   UserMode = 'o'
	WallOps    UserMode = 'w'
	Registered UserMode = 'r' // not a real user mode (flag)
	SecureConn UserMode = 'z'
	SecureOnly UserMode = 'Z'
	HostMask   UserMode = 'x'
)

var (
	SupportedUserModes = UserModes{
		Invisible, Operator, HostMask,
	}
	DefaultChannelModes = ChannelModes{
		NoOutside, OpOnlyTopic,
	}
)

const (
	BanMask         ChannelMode = 'b' // arg
	ChannelCreator  ChannelMode = 'O' // flag
	ChannelOperator ChannelMode = 'o' // arg
	ExceptMask      ChannelMode = 'e' // arg
	InviteMask      ChannelMode = 'I' // arg
	InviteOnly      ChannelMode = 'i' // flag
	Key             ChannelMode = 'k' // flag arg
	Moderated       ChannelMode = 'm' // flag
	NoOutside       ChannelMode = 'n' // flag
	OpOnlyTopic     ChannelMode = 't' // flag
	Private         ChannelMode = 'p' // flag
	Secret          ChannelMode = 's' // flag, deprecated
	UserLimit       ChannelMode = 'l' // flag arg
	Voice           ChannelMode = 'v' // arg
	SecureChan      ChannelMode = 'Z' // arg
)

var (
	SupportedChannelModes = ChannelModes{
		BanMask, ExceptMask, InviteMask, InviteOnly, Key, NoOutside,
		OpOnlyTopic, Private, UserLimit, Secret, SecureChan,
	}
)

//
// commands
//

func (m *ModeCommand) HandleServer(s *Server) {
	client := m.Client()
	target := s.clients.Get(m.nickname)

	if target == nil {
		client.ErrNoSuchNick(m.nickname)
		return
	}

	if client != target && !client.modes.Has(Operator) {
		client.ErrUsersDontMatch()
		return
	}

	changes := make(ModeChanges, 0, len(m.changes))

	for _, change := range m.changes {
		switch change.mode {
		case Invisible, HostMask, WallOps, SecureOnly:
			switch change.op {
			case Add:
				if target.modes.Has(change.mode) {
					continue
				}
				target.modes.Set(change.mode)
				changes = append(changes, change)
			case Remove:
				if !target.modes.Has(change.mode) {
					continue
				}
				target.modes.Unset(change.mode)
				changes = append(changes, change)
			}
		case Operator:
			if change.op == Remove {
				if !target.modes.Has(change.mode) {
					continue
				}
				target.modes.Unset(change.mode)
				changes = append(changes, change)
			}
		}
	}

	if len(changes) > 0 {
		client.Reply(RplModeChanges(client, target, changes))
	} else if client == target {
		client.RplUModeIs(client)
	}
}

func (msg *ChannelModeCommand) HandleServer(server *Server) {
	client := msg.Client()
	channel := server.channels.Get(msg.channel)
	if channel == nil {
		client.ErrNoSuchChannel(msg.channel)
		return
	}

	channel.Mode(client, msg.changes)
}
