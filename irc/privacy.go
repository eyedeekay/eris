package irc

func CanSeeChannel(client *Client, channel *Channel) bool {
	isPrivate := channel.flags.Has(Private)
	isSecret := channel.flags.Has(Secret)

	isMember := channel.members.Has(client)
	isOperator := client.modes.Has(Operator)
	isRegistered := client.modes.Has(Registered)
	isSecure := client.modes.Has(SecureConn)

	if !(isSecret || isPrivate) {
		return true
	}
	if isSecret && (isMember || isOperator) {
		return true
	}
	if isPrivate && (isMember || isOperator || (isRegistered && isSecure)) {
		return true
	}
	return false
}
