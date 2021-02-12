package irc

import (
	"errors"
	"regexp"
	"strings"
	"sync"

	"github.com/goshuirc/girc-go/ircmatch"
)

var (
	ErrNickMissing      = errors.New("nick missing")
	ErrNicknameInUse    = errors.New("nickname in use")
	ErrNicknameMismatch = errors.New("nickname mismatch")
)

func ExpandUserHost(userhost Name) (expanded Name) {
	expanded = userhost
	// fill in missing wildcards for nicks
	if !strings.Contains(expanded.String(), "!") {
		expanded += "!*"
	}
	if !strings.Contains(expanded.String(), "@") {
		expanded += "@*"
	}
	return
}

type ClientLookupSet struct {
	sync.RWMutex
	nicks map[Name]*Client
}

func NewClientLookupSet() *ClientLookupSet {
	return &ClientLookupSet{
		nicks: make(map[Name]*Client),
	}
}

func (clients *ClientLookupSet) Count() int {
	clients.RLock()
	defer clients.RUnlock()

	return len(clients.nicks)
}

func (clients *ClientLookupSet) Get(nick Name) *Client {
	clients.RLock()
	defer clients.RUnlock()

	return clients.nicks[nick.ToLower()]
}

func (clients *ClientLookupSet) Add(client *Client) error {
	if !client.HasNick() {
		return ErrNickMissing
	}
	if clients.Get(client.nick) != nil {
		return ErrNicknameInUse
	}

	clients.Lock()
	defer clients.Unlock()

	clients.nicks[client.Nick().ToLower()] = client
	return nil
}

func (clients *ClientLookupSet) Remove(client *Client) error {
	if !client.HasNick() {
		return ErrNickMissing
	}
	if clients.Get(client.nick) != client {
		return ErrNicknameMismatch
	}

	clients.Lock()
	defer clients.Unlock()

	delete(clients.nicks, client.nick.ToLower())
	return nil
}

func (clients *ClientLookupSet) Range(f func(nick Name, client *Client) bool) {
	clients.RLock()
	defer clients.RUnlock()
	for nick, client := range clients.nicks {
		if !f(nick, client) {
			return
		}
	}
}

func (clients *ClientLookupSet) FindAll(userhost Name) *ClientSet {
	clients.RLock()
	defer clients.RUnlock()

	set := NewClientSet()

	userhost = ExpandUserHost(userhost)
	matcher := ircmatch.MakeMatch(userhost.String())

	var casemappedNickMask string
	for _, client := range clients.nicks {
		casemappedNickMask = client.UserHost(false).String()
		if matcher.Match(casemappedNickMask) {
			set.Add(client)
		}
	}

	return set
}

func (clients *ClientLookupSet) Find(userhost Name) *Client {
	clients.RLock()
	defer clients.RUnlock()

	userhost = ExpandUserHost(userhost)
	matcher := ircmatch.MakeMatch(userhost.String())

	var casemappedNickMask string
	for _, client := range clients.nicks {
		casemappedNickMask = client.UserHost(false).String()
		if matcher.Match(casemappedNickMask) {
			return client
		}
	}

	return nil
}

//
// usermask to regexp
//

type UserMaskSet struct {
	masks  map[Name]bool
	regexp *regexp.Regexp
}

func NewUserMaskSet() *UserMaskSet {
	return &UserMaskSet{
		masks: make(map[Name]bool),
	}
}

func (set *UserMaskSet) Add(mask Name) bool {
	if set.masks[mask] {
		return false
	}
	set.masks[mask] = true
	set.setRegexp()
	return true
}

func (set *UserMaskSet) AddAll(masks []Name) (added bool) {
	for _, mask := range masks {
		if !added && !set.masks[mask] {
			added = true
		}
		set.masks[mask] = true
	}
	set.setRegexp()
	return
}

func (set *UserMaskSet) Remove(mask Name) bool {
	if !set.masks[mask] {
		return false
	}
	delete(set.masks, mask)
	set.setRegexp()
	return true
}

func (set *UserMaskSet) Match(userhost Name) bool {
	if set.regexp == nil {
		return false
	}
	return set.regexp.MatchString(userhost.String())
}

func (set *UserMaskSet) String() string {
	masks := make([]string, len(set.masks))
	index := 0
	for mask := range set.masks {
		masks[index] = mask.String()
		index += 1
	}
	return strings.Join(masks, " ")
}

// Generate a regular expression from the set of user mask
// strings. Masks are split at the two types of wildcards, `*` and
// `?`. All the pieces are meta-escaped. `*` is replaced with `.*`,
// the regexp equivalent. Likewise, `?` is replaced with `.`. The
// parts are re-joined and finally all masks are joined into a big
// or-expression.
func (set *UserMaskSet) setRegexp() {
	if len(set.masks) == 0 {
		set.regexp = nil
		return
	}

	maskExprs := make([]string, len(set.masks))
	index := 0
	for mask := range set.masks {
		manyParts := strings.Split(mask.String(), "*")
		manyExprs := make([]string, len(manyParts))
		for mindex, manyPart := range manyParts {
			oneParts := strings.Split(manyPart, "?")
			oneExprs := make([]string, len(oneParts))
			for oindex, onePart := range oneParts {
				oneExprs[oindex] = regexp.QuoteMeta(onePart)
			}
			manyExprs[mindex] = strings.Join(oneExprs, ".")
		}
		maskExprs[index] = strings.Join(manyExprs, ".*")
	}
	expr := "^" + strings.Join(maskExprs, "|") + "$"
	set.regexp, _ = regexp.Compile(expr)
}
