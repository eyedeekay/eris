package irc

import (
	"fmt"
	"strings"
	"sync"
)

//
// simple types
//

type Counter struct {
	sync.RWMutex
	value int
}

func (c *Counter) Inc() {
	c.Lock()
	defer c.Unlock()
	c.value++
}

func (c *Counter) Dec() {
	c.Lock()
	defer c.Unlock()
	c.value--
}

func (c *Counter) Value() int {
	c.RLock()
	defer c.RUnlock()
	return c.value
}

// ChannelNameMap holds a mapping of channel names to *Channel structs
// that is safe for concurrent readers and writers.
type ChannelNameMap struct {
	sync.RWMutex
	channels map[Name]*Channel
}

// NewChannelNameMap returns a new initialized *ChannelNameMap
func NewChannelNameMap() *ChannelNameMap {
	return &ChannelNameMap{
		channels: make(map[Name]*Channel),
	}
}

// Count returns the number of *Channel9s)
func (c *ChannelNameMap) Count() int {
	c.RLock()
	defer c.RUnlock()
	return len(c.channels)
}

// Range ranges of the *Channels(s) calling f
func (c *ChannelNameMap) Range(f func(kay Name, value *Channel) bool) {
	c.Lock()
	defer c.Unlock()
	for k, v := range c.channels {
		if !f(k, v) {
			return
		}
	}
}

// Get returns a *Channel given a name if it exists or a zero-value *Channel
func (c *ChannelNameMap) Get(name Name) *Channel {
	c.RLock()
	defer c.RUnlock()
	return c.channels[name.ToLower()]
}

// Add adds a new *Channel if not already exists or an error otherwise
func (c *ChannelNameMap) Add(channel *Channel) error {
	c.Lock()
	defer c.Unlock()
	if c.channels[channel.name.ToLower()] != nil {
		return fmt.Errorf("%s: already set", channel.name)
	}
	c.channels[channel.name.ToLower()] = channel
	return nil
}

// Remove removes a *Channel if it exists or an error otherwise
func (c *ChannelNameMap) Remove(channel *Channel) error {
	c.Lock()
	defer c.Unlock()
	if channel != c.channels[channel.name.ToLower()] {
		return fmt.Errorf("%s: mismatch", channel.name)
	}
	delete(c.channels, channel.name.ToLower())
	return nil
}

// UserModeSet holds a mapping of channel modes
type UserModeSet struct {
	sync.RWMutex
	modes map[UserMode]bool
}

// NewUserModeSet returns a new UserModeSet
func NewUserModeSet() *UserModeSet {
	return &UserModeSet{modes: make(map[UserMode]bool)}
}

// Set sets mode
func (set *UserModeSet) Set(mode UserMode) {
	set.Lock()
	defer set.Unlock()
	set.modes[mode] = true
}

// Unset unsets mode
func (set *UserModeSet) Unset(mode UserMode) {
	set.Lock()
	defer set.Unlock()
	delete(set.modes, mode)
}

// Has returns true if the mode is set
func (set *UserModeSet) Has(mode UserMode) bool {
	set.RLock()
	defer set.RUnlock()
	ok, _ := set.modes[mode]
	return ok
}

// Range ranges of the modes calling f
func (set *UserModeSet) Range(f func(mode UserMode) bool) {
	set.RLock()
	defer set.RUnlock()
	for mode := range set.modes {
		if !f(mode) {
			return
		}
	}
}

// String returns a string representing the channel modes
func (set *UserModeSet) String() string {
	set.RLock()
	defer set.RUnlock()

	if len(set.modes) == 0 {
		return ""
	}
	strs := make([]string, len(set.modes))
	index := 0
	for mode := range set.modes {
		strs[index] = mode.String()
		index++
	}
	return strings.Join(strs, "")
}

// ChannelModeSet holds a mapping of channel modes
type ChannelModeSet struct {
	sync.RWMutex
	modes map[ChannelMode]bool
}

// NewChannelModeSet returns a new ChannelModeSet
func NewChannelModeSet() *ChannelModeSet {
	return &ChannelModeSet{modes: make(map[ChannelMode]bool)}
}

// Set sets mode
func (set *ChannelModeSet) Set(mode ChannelMode) {
	set.Lock()
	defer set.Unlock()
	set.modes[mode] = true
}

// Unset unsets mode
func (set *ChannelModeSet) Unset(mode ChannelMode) {
	set.Lock()
	defer set.Unlock()
	delete(set.modes, mode)
}

// Has returns true if the mode is set
func (set *ChannelModeSet) Has(mode ChannelMode) bool {
	set.RLock()
	defer set.RUnlock()
	ok, _ := set.modes[mode]
	return ok
}

// Range ranges of the modes calling f
func (set *ChannelModeSet) Range(f func(mode ChannelMode) bool) {
	set.RLock()
	defer set.RUnlock()
	for mode := range set.modes {
		if !f(mode) {
			return
		}
	}
}

// String returns a string representing the channel modes
func (set *ChannelModeSet) String() string {
	set.RLock()
	defer set.RUnlock()

	if len(set.modes) == 0 {
		return ""
	}
	strs := make([]string, len(set.modes))
	index := 0
	for mode := range set.modes {
		strs[index] = mode.String()
		index++
	}
	return strings.Join(strs, "")
}

type ClientSet struct {
	sync.RWMutex
	clients map[*Client]bool
}

func NewClientSet() *ClientSet {
	return &ClientSet{clients: make(map[*Client]bool)}
}

func (set *ClientSet) Add(client *Client) {
	set.Lock()
	defer set.Unlock()
	set.clients[client] = true
}

func (set *ClientSet) Remove(client *Client) {
	set.Lock()
	defer set.Unlock()
	delete(set.clients, client)
}

func (set *ClientSet) Count() int {
	set.RLock()
	defer set.RUnlock()
	return len(set.clients)
}

func (set *ClientSet) Has(client *Client) bool {
	set.RLock()
	defer set.RUnlock()
	ok, _ := set.clients[client]
	return ok
}

func (set *ClientSet) Range(f func(client *Client) bool) {
	set.RLock()
	defer set.RUnlock()
	for client := range set.clients {
		if !f(client) {
			return
		}
	}
}

type MemberSet struct {
	sync.RWMutex
	members map[*Client]*ChannelModeSet
}

func NewMemberSet() *MemberSet {
	return &MemberSet{members: make(map[*Client]*ChannelModeSet)}
}

func (set *MemberSet) Count() int {
	set.RLock()
	defer set.RUnlock()
	return len(set.members)
}

func (set *MemberSet) Range(f func(client *Client, modes *ChannelModeSet) bool) {
	set.RLock()
	defer set.RUnlock()
	for client, modes := range set.members {
		if !f(client, modes) {
			break
		}
	}
}

func (set *MemberSet) Add(member *Client) {
	set.Lock()
	defer set.Unlock()
	set.members[member] = NewChannelModeSet()
}

func (set *MemberSet) Remove(member *Client) {
	set.Lock()
	defer set.Unlock()
	delete(set.members, member)
}

func (set *MemberSet) Has(member *Client) bool {
	set.RLock()
	defer set.RUnlock()
	_, ok := set.members[member]
	return ok
}

func (set *MemberSet) Get(member *Client) *ChannelModeSet {
	set.RLock()
	defer set.RUnlock()
	return set.members[member]
}

func (set *MemberSet) HasMode(member *Client, mode ChannelMode) bool {
	set.RLock()
	defer set.RUnlock()
	modes, ok := set.members[member]
	if !ok {
		return false
	}
	return modes.Has(mode)
}

type ChannelSet struct {
	sync.RWMutex
	channels map[*Channel]bool
}

func NewChannelSet() *ChannelSet {
	return &ChannelSet{channels: make(map[*Channel]bool)}
}

func (set *ChannelSet) Count() int {
	set.RLock()
	defer set.RUnlock()
	return len(set.channels)
}

func (set *ChannelSet) Add(channel *Channel) {
	set.Lock()
	defer set.Unlock()
	set.channels[channel] = true
}

func (set *ChannelSet) Remove(channel *Channel) {
	set.Lock()
	defer set.Unlock()
	delete(set.channels, channel)
}

func (set *ChannelSet) Range(f func(channel *Channel) bool) {
	set.RLock()
	defer set.RUnlock()
	for channel := range set.channels {
		if !f(channel) {
			break
		}
	}
}

type Identity struct {
	nickname string
	username string
	hostname string
}

func NewIdentity(hostname string, args ...string) *Identity {
	id := &Identity{hostname: hostname}

	if len(args) > 0 {
		id.nickname = args[0]
	}
	if len(args) > 2 {
		id.username = args[1]
	} else {
		id.username = id.nickname
	}

	return id
}

func (id *Identity) Id() Name {
	return NewName(id.username)
}

func (id *Identity) Nick() Name {
	return NewName(id.nickname)
}

func (id *Identity) String() string {
	return fmt.Sprintf("%s!%s@%s", id.nickname, id.username, id.hostname)
}

//
// interfaces
//

type Identifiable interface {
	Id() Name
	Nick() Name
}
