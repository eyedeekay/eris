package irc

import (
	"strconv"
)

type Channel struct {
	flags     *ChannelModeSet
	lists     map[ChannelMode]*UserMaskSet
	key       Text
	members   *MemberSet
	name      Name
	server    *Server
	topic     Text
	userLimit uint64
}

// NewChannel creates a new channel from a `Server` and a `name`
// string, which must be unique on the server.
func NewChannel(s *Server, name Name, addDefaultModes bool) *Channel {
	channel := &Channel{
		flags: NewChannelModeSet(),
		lists: map[ChannelMode]*UserMaskSet{
			BanMask:    NewUserMaskSet(),
			ExceptMask: NewUserMaskSet(),
			InviteMask: NewUserMaskSet(),
		},
		members: NewMemberSet(),
		name:    name,
		server:  s,
	}

	if addDefaultModes {
		for _, mode := range DefaultChannelModes {
			channel.flags.Set(mode)
		}
	}

	s.channels.Add(channel)

	return channel
}

func (channel *Channel) IsEmpty() bool {
	return channel.members.Count() == 0
}

func (channel *Channel) Names(client *Client) {
	client.RplNamReply(channel)
	client.RplEndOfNames(channel)
}

func (channel *Channel) ClientIsOperator(client *Client) bool {
	return client.modes.Has(Operator) || channel.members.HasMode(client, ChannelOperator)
}

func (channel *Channel) Nicks(target *Client) []string {
	isMultiPrefix := (target != nil) && target.capabilities[MultiPrefix]
	channel.members.RLock()
	defer channel.members.RUnlock()
	nicks := make([]string, channel.members.Count())
	i := 0
	channel.members.Range(func(client *Client, modes *ChannelModeSet) bool {
		if isMultiPrefix {
			if modes.Has(ChannelOperator) {
				nicks[i] += "@"
			}
			if modes.Has(Voice) {
				nicks[i] += "+"
			}
		} else {
			if modes.Has(ChannelOperator) {
				nicks[i] += "@"
			} else if modes.Has(Voice) {
				nicks[i] += "+"
			}
		}
		nicks[i] += client.Nick().String()
		i++
		return true
	})
	return nicks
}

func (channel *Channel) Id() Name {
	return channel.name
}

func (channel *Channel) Nick() Name {
	return channel.name
}

func (channel *Channel) String() string {
	return channel.Id().String()
}

// <mode> <mode params>
func (channel *Channel) ModeString(client *Client) (str string) {
	isMember := client.modes.Has(Operator) || channel.members.Has(client)
	showKey := isMember && (channel.key != "")
	showUserLimit := channel.userLimit > 0

	// flags with args
	if showKey {
		str += Key.String()
	}
	if showUserLimit {
		str += UserLimit.String()
	}

	// flags
	channel.flags.Range(func(mode ChannelMode) bool {
		str += mode.String()
		return true
	})

	str = "+" + str

	// args for flags with args: The order must match above to keep
	// positional arguments in place.
	if showKey {
		str += " " + channel.key.String()
	}
	if showUserLimit {
		str += " " + strconv.FormatUint(channel.userLimit, 10)
	}

	return
}

func (channel *Channel) IsFull() bool {
	return (channel.userLimit > 0) &&
		(uint64(channel.members.Count()) >= channel.userLimit)
}

func (channel *Channel) CheckKey(key Text) bool {
	return (channel.key == "") || (channel.key == key)
}

func (channel *Channel) Join(client *Client, key Text) {
	if channel.members.Has(client) {
		// already joined, no message?
		return
	}

	isOperator := channel.ClientIsOperator(client)

	if !isOperator && channel.IsFull() {
		client.ErrChannelIsFull(channel)
		return
	}

	if !isOperator && !channel.CheckKey(key) {
		client.ErrBadChannelKey(channel)
		return
	}

	isInvited := channel.lists[InviteMask].Match(client.UserHost(false))
	if !isOperator && channel.flags.Has(InviteOnly) && !isInvited {
		client.ErrInviteOnlyChan(channel)
		return
	}

	if channel.lists[BanMask].Match(client.UserHost(false)) &&
		!isInvited &&
		!isOperator &&
		!channel.lists[ExceptMask].Match(client.UserHost(false)) {
		client.ErrBannedFromChan(channel)
		return
	}

	client.channels.Add(channel)
	channel.members.Add(client)
	if channel.members.Count() == 1 {
		channel.members.Get(client).Set(ChannelCreator)
		channel.members.Get(client).Set(ChannelOperator)
	}

	reply := RplJoin(client, channel)
	channel.members.Range(func(member *Client, _ *ChannelModeSet) bool {
		member.Reply(reply)
		return true
	})
	channel.GetTopic(client)
	channel.Names(client)
}

func (channel *Channel) Part(client *Client, message Text) {
	if !channel.members.Has(client) {
		client.ErrNotOnChannel(channel)
		return
	}

	reply := RplPart(client, channel, message)
	channel.members.Range(func(member *Client, _ *ChannelModeSet) bool {
		member.Reply(reply)
		return true
	})
	channel.Quit(client)
}

func (channel *Channel) GetTopic(client *Client) {
	if !(channel.ClientIsOperator(client) || channel.members.Has(client)) {
		client.ErrNotOnChannel(channel)
		return
	}

	if channel.topic == "" {
		client.RplNoTopic(channel)
		return
	}

	client.RplTopic(channel)
}

func (channel *Channel) SetTopic(client *Client, topic Text) {
	if !(channel.ClientIsOperator(client) || channel.members.Has(client)) {
		client.ErrNotOnChannel(channel)
		return
	}

	if channel.flags.Has(OpOnlyTopic) && !channel.ClientIsOperator(client) {
		client.ErrChanOPrivIsNeeded(channel)
		return
	}

	channel.topic = topic

	reply := RplTopicMsg(client, channel)
	channel.members.Range(func(member *Client, _ *ChannelModeSet) bool {
		member.Reply(reply)
		return true
	})
}

func (channel *Channel) CanSpeak(client *Client) bool {
	if channel.ClientIsOperator(client) {
		return true
	}
	if channel.flags.Has(NoOutside) && !channel.members.Has(client) {
		return false
	}
	if channel.flags.Has(Moderated) && !(channel.members.HasMode(client, Voice) ||
		channel.members.HasMode(client, ChannelOperator)) {
		return false
	}
	if channel.flags.Has(SecureChan) && !client.modes.Has(SecureConn) {
		return false
	}
	return true
}

func (channel *Channel) PrivMsg(client *Client, message Text) {
	if !channel.CanSpeak(client) {
		client.ErrCannotSendToChan(channel)
		return
	}
	reply := RplPrivMsg(client, channel, message)
	channel.members.Range(func(member *Client, _ *ChannelModeSet) bool {
		if member == client {
			return true
		}
		client.server.metrics.Counter("client", "messages").Inc()
		member.Reply(reply)
		return true
	})
}

func (channel *Channel) applyModeFlag(client *Client, mode ChannelMode,
	op ModeOp) bool {
	if !channel.ClientIsOperator(client) {
		client.ErrChanOPrivIsNeeded(channel)
		return false
	}

	switch op {
	case Add:
		if channel.flags.Has(mode) {
			return false
		}
		channel.flags.Set(mode)
		return true

	case Remove:
		if !channel.flags.Has(mode) {
			return false
		}
		channel.flags.Unset(mode)
		return true
	}
	return false
}

func (channel *Channel) applyModeMember(client *Client, mode ChannelMode,
	op ModeOp, nick Name) bool {
	if !channel.ClientIsOperator(client) {
		client.ErrChanOPrivIsNeeded(channel)
		return false
	}

	if nick == "" {
		client.ErrNeedMoreParams("MODE")
		return false
	}

	target := channel.server.clients.Get(nick)
	if target == nil {
		client.ErrNoSuchNick(nick)
		return false
	}

	if !channel.members.Has(target) {
		client.ErrUserNotInChannel(channel, target)
		return false
	}

	switch op {
	case Add:
		if channel.members.Get(target).Has(mode) {
			return false
		}
		channel.members.Get(target).Set(mode)
		return true

	case Remove:
		if !channel.members.Get(target).Has(mode) {
			return false
		}
		channel.members.Get(target).Unset(mode)
		return true
	}
	return false
}

func (channel *Channel) ShowMaskList(client *Client, mode ChannelMode) {
	for lmask := range channel.lists[mode].masks {
		client.RplMaskList(mode, channel, lmask)
	}
	client.RplEndOfMaskList(mode, channel)
}

func (channel *Channel) applyModeMask(client *Client, mode ChannelMode, op ModeOp,
	mask Name) bool {
	list := channel.lists[mode]
	if list == nil {
		// This should never happen, but better safe than panicky.
		return false
	}

	if (op == List) || (mask == "") {
		channel.ShowMaskList(client, mode)
		return false
	}

	if !channel.ClientIsOperator(client) {
		client.ErrChanOPrivIsNeeded(channel)
		return false
	}

	if op == Add {
		return list.Add(mask)
	}

	if op == Remove {
		return list.Remove(mask)
	}

	return false
}

func (channel *Channel) applyMode(client *Client, change *ChannelModeChange) bool {
	switch change.mode {
	case BanMask, ExceptMask, InviteMask:
		return channel.applyModeMask(client, change.mode, change.op,
			NewName(change.arg))

	case InviteOnly, Moderated, NoOutside, OpOnlyTopic, Private, Secret, SecureChan:
		return channel.applyModeFlag(client, change.mode, change.op)

	case Key:
		if !channel.ClientIsOperator(client) {
			client.ErrChanOPrivIsNeeded(channel)
			return false
		}

		switch change.op {
		case Add:
			if change.arg == "" {
				client.ErrNeedMoreParams("MODE")
				return false
			}
			key := NewText(change.arg)
			if key == channel.key {
				return false
			}

			channel.key = key
			return true

		case Remove:
			channel.key = ""
			return true
		}

	case UserLimit:
		limit, err := strconv.ParseUint(change.arg, 10, 64)
		if err != nil {
			client.ErrNeedMoreParams("MODE")
			return false
		}
		if (limit == 0) || (limit == channel.userLimit) {
			return false
		}

		channel.userLimit = limit
		return true

	case ChannelOperator, Voice:
		return channel.applyModeMember(client, change.mode, change.op,
			NewName(change.arg))

	default:
		client.ErrUnknownMode(change.mode, channel)
	}
	return false
}

func (channel *Channel) Mode(client *Client, changes ChannelModeChanges) {
	if len(changes) == 0 {
		client.RplChannelModeIs(channel)
		return
	}

	applied := make(ChannelModeChanges, 0)
	for _, change := range changes {
		if channel.applyMode(client, change) {
			applied = append(applied, change)
		}
	}

	if len(applied) > 0 {
		reply := RplChannelMode(client, channel, applied)
		channel.members.Range(func(member *Client, _ *ChannelModeSet) bool {
			member.Reply(reply)
			return true
		})
	}
}

func (channel *Channel) Notice(client *Client, message Text) {
	if !channel.CanSpeak(client) {
		client.ErrCannotSendToChan(channel)
		return
	}
	reply := RplNotice(client, channel, message)
	channel.members.Range(func(member *Client, _ *ChannelModeSet) bool {
		if member == client {
			return true
		}
		client.server.metrics.Counter("client", "messages").Inc()
		member.Reply(reply)
		return true
	})
}

func (channel *Channel) Quit(client *Client) {
	channel.members.Remove(client)
	// XXX: Race Condition from client.destroy()
	//      Do we need to?
	// client.channels.Remove(channel)

	if channel.IsEmpty() {
		channel.server.channels.Remove(channel)
	}
}

func (channel *Channel) Kick(client *Client, target *Client, comment Text) {
	if !(channel.ClientIsOperator(client) || channel.members.Has(client)) {
		client.ErrNotOnChannel(channel)
		return
	}
	if !channel.ClientIsOperator(client) {
		client.ErrChanOPrivIsNeeded(channel)
		return
	}
	if !channel.members.Has(target) {
		client.ErrUserNotInChannel(channel, target)
		return
	}

	reply := RplKick(channel, client, target, comment)
	channel.members.Range(func(member *Client, _ *ChannelModeSet) bool {
		member.Reply(reply)
		return true
	})
	channel.Quit(target)
}

func (channel *Channel) Invite(invitee *Client, inviter *Client) {
	if channel.flags.Has(InviteOnly) && !channel.ClientIsOperator(inviter) {
		inviter.ErrChanOPrivIsNeeded(channel)
		return
	}

	if !channel.members.Has(inviter) && !channel.ClientIsOperator(inviter) {
		inviter.ErrNotOnChannel(channel)
		return
	}

	if channel.flags.Has(InviteOnly) {
		channel.lists[InviteMask].Add(invitee.UserHost(false))
	}

	inviter.RplInviting(invitee, channel.name)
	invitee.Reply(RplInviteMsg(inviter, invitee, channel.name))
	if invitee.modes.Has(Away) {
		inviter.RplAway(invitee)
	}
}
