package irc

import (
	"fmt"
	"strings"
	"time"
)

type ReplyCode interface {
	String() string
}

type StringCode string

func (code StringCode) String() string {
	return string(code)
}

type NumericCode uint

func (code NumericCode) String() string {
	return fmt.Sprintf("%03d", code)
}

func NewStringReply(source Identifiable, code StringCode,
	format string, args ...interface{}) string {
	var header string
	if source == nil {
		header = code.String() + " "
	} else {
		header = fmt.Sprintf(":%s %s ", source, code)
	}
	var message string
	if len(args) > 0 {
		message = fmt.Sprintf(format, args...)
	} else {
		message = format
	}
	return header + message
}

func NewNumericReply(target *Client, code NumericCode,
	format string, args ...interface{}) string {
	header := fmt.Sprintf(":%s %s %s ", target.server.Id(), code, target.Nick())
	var message string
	if len(args) > 0 {
		message = fmt.Sprintf(format, args...)
	} else {
		message = format
	}
	return header + message
}

func (target *Client) NumericReply(code NumericCode,
	format string, args ...interface{}) {
	target.Reply(NewNumericReply(target, code, format, args...))
}

//
// multiline replies
//

func joinedLen(names []string) int {
	var l = len(names) - 1 // " " between names
	for _, name := range names {
		l += len(name)
	}
	return l
}

func (target *Client) MultilineReply(names []string, code NumericCode, format string,
	args ...interface{}) {
	baseLen := len(NewNumericReply(target, code, format))
	tooLong := func(names []string) bool {
		return (baseLen + joinedLen(names)) > MAX_REPLY_LEN
	}
	argsAndNames := func(names []string) []interface{} {
		return append(args, strings.Join(names, " "))
	}
	from, to := 0, 1
	for to < len(names) {
		if (from < (to - 1)) && tooLong(names[from:to]) {
			target.NumericReply(code, format, argsAndNames(names[from:to-1])...)
			from = to - 1
		} else {
			to += 1
		}
	}
	if from < len(names) {
		target.NumericReply(code, format, argsAndNames(names[from:])...)
	}
}

//
// messaging replies
//

func RplPrivMsg(source Identifiable, target Identifiable, message Text) string {
	return NewStringReply(source, PRIVMSG, "%s :%s", target.Nick(), message)
}

func RplCTCPAction(source Identifiable, target Identifiable, action CTCPText) string {
	return RplPrivMsg(source, target, NewText(fmt.Sprintf("\x01ACTION %s\x01", action)))
}

func RplNotice(source Identifiable, target Identifiable, message Text) string {
	return NewStringReply(source, NOTICE, "%s :%s", target.Nick(), message)
}

func RplNick(source Identifiable, newNick Name) string {
	return NewStringReply(source, NICK, newNick.String())
}

func RplJoin(client *Client, channel *Channel) string {
	return NewStringReply(client, JOIN, channel.name.String())
}

func RplPart(client *Client, channel *Channel, message Text) string {
	return NewStringReply(client, PART, "%s :%s", channel, message)
}

func RplModeChanges(client *Client, target *Client, changes ModeChanges) string {
	return NewStringReply(client, MODE, "%s :%s", target.Nick(), changes)
}

func RplChannelMode(client *Client, channel *Channel,
	changes ChannelModeChanges) string {
	return NewStringReply(client, MODE, "%s %s", channel, changes)
}

func RplTopicMsg(source Identifiable, channel *Channel) string {
	return NewStringReply(source, TOPIC, "%s :%s", channel, channel.topic)
}

func RplPing(target Identifiable) string {
	return NewStringReply(nil, PING, ":%s", target.Nick())
}

func RplPong(client *Client, msg Text) string {
	// #5: IRC for Android will time out if it doesn't get the prefix back.
	return NewStringReply(client, PONG, "%s :%s", client.server, msg.String())
}

func RplQuit(client *Client, message Text) string {
	return NewStringReply(client, QUIT, ":%s", message)
}

func RplError(message string) string {
	return NewStringReply(nil, ERROR, ":%s", message)
}

func RplInviteMsg(inviter *Client, invitee *Client, channel Name) string {
	return NewStringReply(inviter, INVITE, "%s :%s", invitee.Nick(), channel)
}

func RplKick(channel *Channel, client *Client, target *Client, comment Text) string {
	return NewStringReply(client, KICK, "%s %s :%s",
		channel, target.Nick(), comment)
}

func RplKill(client *Client, target *Client, comment Text) string {
	return NewStringReply(client, KICK,
		"%s :%s", target.Nick(), comment)
}

func RplCap(client *Client, subCommand CapSubCommand, arg interface{}) string {
	// client.server needs to be here to workaround a parsing bug in weechat 1.4
	// and let it connect to the server (otherwise it doesn't respond to the CAP
	// message with anything and just hangs on connection)
	return NewStringReply(client.server, CAP, "%s %s :%s", client.Nick(), subCommand, arg)
}

// numeric replies

func (target *Client) RplWelcome() {
	target.NumericReply(
		RPL_WELCOME,
		":Welcome to the %s Internet Relay Network %s",
		target.server.Network(),
		target.Id(),
	)
}

func (target *Client) RplYourHost() {
	target.NumericReply(
		RPL_YOURHOST,
		":Your host is %s, running %s",
		target.server.name,
		FullVersion(),
	)
}

func (target *Client) RplCreated() {
	target.NumericReply(RPL_CREATED,
		":This server was created %s", target.server.ctime.Format(time.RFC1123))
}

func (target *Client) RplMyInfo() {
	target.NumericReply(
		RPL_MYINFO,
		"%s %s %s %s",
		target.server.name,
		FullVersion(),
		SupportedUserModes,
		SupportedChannelModes,
	)
}

func (target *Client) RplUModeIs(client *Client) {
	target.NumericReply(RPL_UMODEIS, client.ModeString())
}

func (target *Client) RplNoTopic(channel *Channel) {
	target.NumericReply(RPL_NOTOPIC,
		"%s :No topic is set", channel.name)
}

func (target *Client) RplTopic(channel *Channel) {
	target.NumericReply(RPL_TOPIC,
		"%s :%s", channel.name, channel.topic)
}

// <nick> <channel>
// NB: correction in errata
func (target *Client) RplInvitingMsg(invitee *Client, channel Name) {
	target.NumericReply(RPL_INVITING,
		"%s %s", invitee.Nick(), channel)
}

func (target *Client) RplEndOfNames(channel *Channel) {
	target.NumericReply(RPL_ENDOFNAMES,
		"%s :End of NAMES list", channel.name)
}

// :You are now an IRC operator
func (target *Client) RplYoureOper() {
	target.NumericReply(RPL_YOUREOPER,
		":You are now an IRC operator")
}

// <config file> :Rehashing
func (target *Client) RplRehashing() {
	target.NumericReply(
		RPL_REHASHING,
		"%s :Rehashing",
		target.server.config.Name(),
	)
}

func (target *Client) RplWhois(client *Client) {
	target.RplWhoisUser(client)
	if client.modes.Has(Operator) {
		target.RplWhoisOperator(client)
	}
	target.RplWhoisIdle(client)
	target.RplWhoisChannels(client)

	if client.modes.Has(SecureConn) {
		target.RplWhoisSecure(client)
	}
	target.RplWhoisServer(client)
	target.RplWhoisLoggedIn(client)
	target.RplEndOfWhois(client)
}

func (target *Client) RplWhoisUser(client *Client) {
	var clientHost Name

	if target.modes.Has(Operator) || !client.modes.Has(HostMask) {
		clientHost = client.hostname
	} else {
		clientHost = client.hostmask
	}

	target.NumericReply(
		RPL_WHOISUSER,
		"%s %s %s * :%s",
		client.Nick(),
		client.username,
		clientHost,
		client.realname,
	)
}

func (target *Client) RplWhoisOperator(client *Client) {
	target.NumericReply(RPL_WHOISOPERATOR,
		"%s :is an IRC operator", client.Nick())
}

func (target *Client) RplWhoisSecure(client *Client) {
	target.NumericReply(
		RPL_WHOISSECURE,
		"%s :is using a secure connection",
		client.Nick(),
	)
}

func (target *Client) RplWhoisIdle(client *Client) {
	target.NumericReply(RPL_WHOISIDLE,
		"%s %d %d :seconds idle, signon time",
		client.Nick(), client.IdleSeconds(), client.SignonTime())
}

func (target *Client) RplWhoisLoggedIn(client *Client) {
	if client.sasl.Id() == "" {
		return
	}

	target.NumericReply(
		RPL_WHOISLOGGEDIN,
		"%s %s :Is logged in as",
		client.Nick(),
		client.sasl.Id(),
	)
}

func (target *Client) RplWhoisServer(client *Client) {
	target.NumericReply(
		RPL_WHOISSERVER,
		"%s %s :%s",
		client.Nick(),
		client.Server(),
		client.ServerInfo(),
	)
}

func (target *Client) RplEndOfWhois(client *Client) {
	target.NumericReply(
		RPL_ENDOFWHOIS,
		"%s :End of WHOIS list",
		client.Nick(),
	)
}

func (target *Client) RplChannelModeIs(channel *Channel) {
	target.NumericReply(RPL_CHANNELMODEIS,
		"%s %s", channel, channel.ModeString(target))
}

// <channel> <user> <host> <server> <nick> ( "H" / "G" ) ["*"] [ ( "@" / "+" ) ]
// :<hopcount> <real name>
func (target *Client) RplWhoReply(channel *Channel, client *Client) {
	var clientHost Name

	if target.modes.Has(Operator) || !client.modes.Has(HostMask) {
		clientHost = client.hostname
	} else {
		clientHost = client.hostmask
	}

	channelName := "*"
	flags := ""

	if client.modes.Has(Away) {
		flags = "G"
	} else {
		flags = "H"
	}
	if client.modes.Has(Operator) {
		flags += "*"
	}

	if channel != nil {
		channelName = channel.name.String()
		if target.capabilities[MultiPrefix] {
			if channel.members.Get(client).Has(ChannelOperator) {
				flags += "@"
			}
			if channel.members.Get(client).Has(Voice) {
				flags += "+"
			}
		} else {
			if channel.members.Get(client).Has(ChannelOperator) {
				flags += "@"
			} else if channel.members.Get(client).Has(Voice) {
				flags += "+"
			}
		}
	}
	target.NumericReply(
		RPL_WHOREPLY,
		"%s %s %s %s %s %s :%d %s",
		channelName,
		client.username,
		clientHost,
		client.server.name,
		client.Nick(),
		flags,
		client.hops,
		client.realname,
	)
}

// <name> :End of WHO list
func (target *Client) RplEndOfWho(name Name) {
	target.NumericReply(RPL_ENDOFWHO,
		"%s :End of WHO list", name)
}

func (target *Client) RplMaskList(mode ChannelMode, channel *Channel, mask Name) {
	switch mode {
	case BanMask:
		target.RplBanList(channel, mask)

	case ExceptMask:
		target.RplExceptList(channel, mask)

	case InviteMask:
		target.RplInviteList(channel, mask)
	}
}

func (target *Client) RplEndOfMaskList(mode ChannelMode, channel *Channel) {
	switch mode {
	case BanMask:
		target.RplEndOfBanList(channel)

	case ExceptMask:
		target.RplEndOfExceptList(channel)

	case InviteMask:
		target.RplEndOfInviteList(channel)
	}
}

func (target *Client) RplBanList(channel *Channel, mask Name) {
	target.NumericReply(RPL_BANLIST,
		"%s %s", channel, mask)
}

func (target *Client) RplEndOfBanList(channel *Channel) {
	target.NumericReply(RPL_ENDOFBANLIST,
		"%s :End of channel ban list", channel)
}

func (target *Client) RplExceptList(channel *Channel, mask Name) {
	target.NumericReply(RPL_EXCEPTLIST,
		"%s %s", channel, mask)
}

func (target *Client) RplEndOfExceptList(channel *Channel) {
	target.NumericReply(RPL_ENDOFEXCEPTLIST,
		"%s :End of channel exception list", channel)
}

func (target *Client) RplInviteList(channel *Channel, mask Name) {
	target.NumericReply(RPL_INVITELIST,
		"%s %s", channel, mask)
}

func (target *Client) RplEndOfInviteList(channel *Channel) {
	target.NumericReply(RPL_ENDOFINVITELIST,
		"%s :End of channel invite list", channel)
}

func (target *Client) RplNowAway() {
	target.NumericReply(RPL_NOWAWAY,
		":You have been marked as being away")
}

func (target *Client) RplUnAway() {
	target.NumericReply(RPL_UNAWAY,
		":You are no longer marked as being away")
}

func (target *Client) RplAway(client *Client) {
	target.NumericReply(RPL_AWAY,
		"%s :%s", client.Nick(), client.awayMessage)
}

func (target *Client) RplIsOn(nicks []string) {
	target.NumericReply(RPL_ISON,
		":%s", strings.Join(nicks, " "))
}

func (target *Client) RplMOTDStart() {
	target.NumericReply(RPL_MOTDSTART,
		":- %s Message of the day - ", target.server.name)
}

func (target *Client) RplMOTD(line string) {
	target.NumericReply(RPL_MOTD,
		":- %s", line)
}

func (target *Client) RplMOTDEnd() {
	target.NumericReply(RPL_ENDOFMOTD,
		":End of MOTD command")
}

func (target *Client) RplList(channel *Channel) {
	target.NumericReply(
		RPL_LIST,
		"%s %d :%s",
		channel,
		channel.members.Count(),
		channel.topic,
	)
}

func (target *Client) RplListEnd(server *Server) {
	target.NumericReply(RPL_LISTEND,
		":End of LIST")
}

func (target *Client) RplNamReply(channel *Channel) {
	target.MultilineReply(channel.Nicks(target), RPL_NAMREPLY,
		"= %s :%s", channel)
}

func (target *Client) RplWhoisChannels(client *Client) {
	target.MultilineReply(
		client.WhoisChannelsNames(target),
		RPL_WHOISCHANNELS,
		"%s :%s",
		client.Nick(),
	)
}

func (target *Client) RplVersion() {
	target.NumericReply(
		RPL_VERSION,
		"%s %s",
		FullVersion(),
		target.server.name,
	)
}

func (target *Client) RplInviting(invitee *Client, channel Name) {
	target.NumericReply(RPL_INVITING,
		"%s %s", invitee.Nick(), channel)
}

func (target *Client) RplTime() {
	target.NumericReply(RPL_TIME,
		"%s :%s", target.server.name, time.Now().Format(time.RFC1123))
}

func (target *Client) RplLUserClient() {
	target.NumericReply(
		RPL_LUSERCLIENT,
		"There are %d users and %d invisible on %d servers",
		// TODO: count global visible users
		target.server.clients.Count(),
		// TODO: count global invisible users
		0,
		// TODO: count global server connections
		1,
	)
}

func (target *Client) RplLUserUnknown() {
	nUnknown := target.server.connections.Value() - target.server.clients.Count()

	if nUnknown == 0 {
		return
	}

	target.NumericReply(
		RPL_LUSERUNKNOWN,
		"%d :unknown connections(s)",
		nUnknown,
	)
}

func (target *Client) RplLUserChannels() {
	nChannels := target.server.channels.Count()
	if nChannels == 0 {
		return
	}

	target.NumericReply(
		RPL_LUSERCHANNELS,
		"%d :channel(s) formed",
		nChannels,
	)
}

func (target *Client) RplLUserOp() {
	nOperators := 0
	target.server.clients.Range(func(_ Name, client *Client) bool {
		if client.modes.Has(Operator) {
			nOperators++
		}
		return true
	})

	if nOperators == 0 {
		return
	}

	target.NumericReply(
		RPL_LUSEROP,
		"%d :operator(s) online",
		// TODO: state store should know this
		nOperators,
	)
}

func (target *Client) RplLUserMe() {
	target.NumericReply(
		RPL_LUSERME,
		"I have %d clients and %d servers",
		target.server.clients.Count(),
		// TODO: count server connections
		1,
	)
}

func (target *Client) RplWhoWasUser(whoWas *WhoWas) {
	var whoWasHost Name

	if target.modes.Has(Operator) {
		whoWasHost = whoWas.hostname
	} else {
		whoWasHost = whoWas.hostmask
	}

	target.NumericReply(
		RPL_WHOWASUSER,
		"%s %s %s * :%s",
		whoWas.nickname,
		whoWas.username,
		whoWasHost,
		whoWas.realname,
	)
}

func (target *Client) RplEndOfWhoWas(nickname Name) {
	target.NumericReply(RPL_ENDOFWHOWAS,
		"%s :End of WHOWAS", nickname)
}

//
// errors (also numeric)
//

func (target *Client) ErrAlreadyRegistered() {
	target.NumericReply(ERR_ALREADYREGISTRED,
		":You may not reregister")
}

func (target *Client) ErrNickNameInUse(nick Name) {
	target.NumericReply(ERR_NICKNAMEINUSE,
		"%s :Nickname is already in use", nick)
}

func (target *Client) ErrUnknownCommand(code StringCode) {
	target.NumericReply(ERR_UNKNOWNCOMMAND,
		"%s :Unknown command", code)
}

func (target *Client) ErrUsersDontMatch() {
	target.NumericReply(ERR_USERSDONTMATCH,
		":Cannot change mode for other users")
}

func (target *Client) ErrNeedMoreParams(command StringCode) {
	target.NumericReply(ERR_NEEDMOREPARAMS,
		"%s :Not enough parameters", command)
}

func (target *Client) ErrNoSuchChannel(channel Name) {
	target.NumericReply(ERR_NOSUCHCHANNEL,
		"%s :No such channel", channel)
}

func (target *Client) ErrUserOnChannel(channel *Channel, member *Client) {
	target.NumericReply(ERR_USERONCHANNEL,
		"%s %s :is already on channel", member.Nick(), channel.name)
}

func (target *Client) ErrNotOnChannel(channel *Channel) {
	target.NumericReply(ERR_NOTONCHANNEL,
		"%s :You're not on that channel", channel.name)
}

func (target *Client) ErrInviteOnlyChannel(channel *Channel) {
	target.NumericReply(ERR_INVITEONLYCHAN,
		"%s :Cannot join channel (+i)", channel.name)
}

func (target *Client) ErrBadChannelKey(channel *Channel) {
	target.NumericReply(ERR_BADCHANNELKEY,
		"%s :Cannot join channel (+k)", channel.name)
}

func (target *Client) ErrNoSuchNick(nick Name) {
	target.NumericReply(ERR_NOSUCHNICK,
		"%s :No such nick/channel", nick)
}

func (target *Client) ErrPasswdMismatch() {
	target.NumericReply(ERR_PASSWDMISMATCH, ":Password incorrect")
}

func (target *Client) ErrNoChanModes(channel *Channel) {
	target.NumericReply(ERR_NOCHANMODES,
		"%s :Channel doesn't support modes", channel)
}

func (target *Client) ErrNoPrivileges() {
	target.NumericReply(ERR_NOPRIVILEGES, ":Permission Denied")
}

func (target *Client) ErrRestricted() {
	target.NumericReply(ERR_RESTRICTED, ":Your connection is restricted!")
}

func (target *Client) ErrNoSuchServer(server Name) {
	target.NumericReply(ERR_NOSUCHSERVER, "%s :No such server", server)
}

func (target *Client) ErrUserNotInChannel(channel *Channel, client *Client) {
	target.NumericReply(ERR_USERNOTINCHANNEL,
		"%s %s :They aren't on that channel", client.Nick(), channel)
}

func (target *Client) ErrCannotSendToChan(channel *Channel) {
	target.NumericReply(ERR_CANNOTSENDTOCHAN,
		"%s :Cannot send to channel", channel)
}

func (target *Client) ErrCannotSendToUser(nick Name, reason string) {
	target.NumericReply(
		ERR_CANNOTSENDTOUSER,
		":Cannot send to user %s (%s)",
		nick,
		reason,
	)
}

// <channel> :You're not channel operator
func (target *Client) ErrChanOPrivIsNeeded(channel *Channel) {
	target.NumericReply(ERR_CHANOPRIVSNEEDED,
		"%s :You're not channel operator", channel)
}

func (target *Client) ErrNoMOTD() {
	target.NumericReply(ERR_NOMOTD, ":MOTD File is missing")
}

func (target *Client) ErrNoNicknameGiven() {
	target.NumericReply(ERR_NONICKNAMEGIVEN, ":No nickname given")
}

func (target *Client) ErrErroneusNickname(nick Name) {
	target.NumericReply(ERR_ERRONEUSNICKNAME,
		"%s :Erroneous nickname", nick)
}

func (target *Client) ErrUnknownMode(mode ChannelMode, channel *Channel) {
	target.NumericReply(ERR_UNKNOWNMODE,
		"%s :is unknown mode char to me for %s", mode, channel)
}

func (target *Client) ErrConfiguredMode(mode ChannelMode) {
	target.NumericReply(ERR_UNKNOWNMODE,
		"%s :can only change this mode in daemon configuration", mode)
}

func (target *Client) ErrChannelIsFull(channel *Channel) {
	target.NumericReply(ERR_CHANNELISFULL,
		"%s :Cannot join channel (+l)", channel)
}

func (target *Client) ErrWasNoSuchNick(nickname Name) {
	target.NumericReply(ERR_WASNOSUCHNICK,
		"%s :There was no such nickname", nickname)
}

func (target *Client) ErrInvalidCapCmd(subCommand CapSubCommand) {
	target.NumericReply(ERR_INVALIDCAPCMD,
		"%s :Invalid CAP subcommand", subCommand)
}

func (target *Client) ErrBannedFromChan(channel *Channel) {
	target.NumericReply(ERR_BANNEDFROMCHAN,
		"%s :Cannot join channel (+b)", channel)
}

func (target *Client) ErrInviteOnlyChan(channel *Channel) {
	target.NumericReply(ERR_INVITEONLYCHAN,
		"%s :Cannot join channel (+i)", channel)
}

//
// SASL Errors / Replies
//

func RplAuthenticate(client *Client, arg string) string {
	return NewStringReply(client.server, AUTHENTICATE, arg)
}

func (target *Client) RplLoggedIn(authcid string) {
	target.NumericReply(
		RPL_LOGGEDIN,
		"%s %s :You are now logged in as %s",
		target, authcid, authcid,
	)
}

func (target *Client) RplLoggedOut() {
	target.NumericReply(
		RPL_LOGGEDIN,
		"%s :You are now logged out",
		target,
	)
}

func (target *Client) ErrNickLocked() {
	target.NumericReply(
		ERR_NICKLOCKED,
		"%s :You must use a nick assigned to you",
		target.Nick(),
	)
}

func (target *Client) RplSaslSuccess() {
	target.NumericReply(
		RPL_SASLSUCCESS,
		"%s :SASL authentication successful",
		target.Nick(),
	)
}

func (target *Client) ErrSaslFail(message string) {
	target.NumericReply(
		ERR_SASLFAIL,
		"%s :SASL authentication failed: %s",
		target.Nick(), message,
	)
}

func (target *Client) ErrSaslTooLong() {
	target.NumericReply(
		ERR_SASLFAIL,
		"%s :SASL message too long",
		target.Nick(),
	)
}

func (target *Client) ErrSaslAborted() {
	target.NumericReply(
		ERR_SASLABORTED,
		"%s :SASL authentication aborted",
		target.Nick(),
	)
}

func (target *Client) ErrSaslAlready() {
	target.NumericReply(
		ERR_SASLALREADY,
		"%s :You have already authenticated using SASL",
		target.Nick(),
	)
}

func (target *Client) RplSaslMechs(mechs ...string) {
	target.NumericReply(
		RPL_SASLMECHS,
		"%s %s :are available SASL mechanisms",
		target.Nick(),
		strings.Join(mechs, ","),
	)
}
