// Package order manages the bookkeeping and utilies required
// for users to create an 'order' meaning they have requested
// delegations for a certain resource.
//
// Copyright (c) 2016 CloudFlare, Inc.
package order

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/cloudflare/redoctober/hipchat"
)

const (
	NewOrder       = "%s has created an order for the label %s. requesting %d delegations for %s"
	NewOrderLink   = "@%s - https://%s?%s"
	OrderFulfilled = "%s has had order %s fulfilled."
	NewDelegation  = "%s has delegated the label %s to %s (per order %s) for %s"
)

type Order struct {
	Creator string
	Users   []string
	Num     string

	TimeRequested     time.Time
	DurationRequested time.Duration
	Delegated         int
	OwnersDelegated   []string
	Owners            []string
	Labels            []string
}

type OrderIndex struct {
	OrderFor string

	OrderId     string
	OrderOwners []string
}

// Orders represents a mapping of Order IDs to Orders. This structure
// is useful for looking up information about individual Orders and
// whether or not an order has been fulfilled. Orders that have been
// fulfilled will be removed from the structure.
//
// All mutations and lookups of the outstanding orders go through the
// Orderer methods below, which hold the Orderer's lock for the whole
// find-check-update sequence. This makes every operation on an order a
// single recoverable transaction: concurrent delegations, fulfillments
// and cancellations of overlapping orders always observe the same
// order bound to its order number, creator, target users, label set
// and owners.
type Orderer struct {
	Orders        map[string]Order
	Hipchat       hipchat.HipchatClient
	AlternateName string

	mu sync.Mutex
}

func CreateOrder(name, orderNum string, time time.Time, duration time.Duration, adminsDelegated, contacts, users, labels []string, numDelegated int) (ord Order) {
	ord.Creator = name
	ord.Num = orderNum
	ord.Labels = labels
	ord.TimeRequested = time
	ord.DurationRequested = duration
	ord.OwnersDelegated = adminsDelegated
	ord.Owners = contacts
	ord.Delegated = numDelegated
	ord.Users = users
	return
}

func GenerateNum() (num string) {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// NewOrderer will create a new map of Orders
func NewOrderer(hipchatClient hipchat.HipchatClient) *Orderer {
	return &Orderer{
		Orders:        make(map[string]Order),
		Hipchat:       hipchatClient,
		AlternateName: "HipchatName",
	}
}

// notify is a generic function for using a notifier, but it checks to make
// sure that there is a notifier available, since there won't always be.
func notify(o *Orderer, msg, color string) {
	o.Hipchat.Notify(msg, color)
}
func (o *Orderer) NotifyNewOrder(duration, orderNum string, names, labels []string, uses int, owners map[string]string) {
	labelList := ""
	for i, label := range labels {
		if i == 0 {
			labelList += label
		} else {
			// Never include spaces in something go URI encodes. Go will
			// add a + to the string, instead of a %20
			labelList += "," + label
		}
	}
	nameList := ""
	for i, name := range names {
		if i == 0 {
			nameList += name
		} else {
			// Never include spaces in something go URI encodes. Go will
			// add a + to the string, instead of a %20
			nameList += "," + name
		}
	}

	n := fmt.Sprintf(NewOrder, nameList, labelList, uses, duration)
	notify(o, n, hipchat.RedBackground)
	for owner, hipchatName := range owners {
		queryParams := url.Values{
			"delegator": {owner},
			"label":     {labelList},
			"duration":  {duration},
			"uses":      {strconv.Itoa(uses)},
			"ordernum":  {orderNum},
			"delegatee": {nameList},
		}.Encode()
		notify(o, fmt.Sprintf(NewOrderLink, hipchatName, o.Hipchat.RoHost, queryParams), hipchat.GreenBackground)
	}
}

func (o *Orderer) NotifyDelegation(delegator, delegatee, orderNum, duration string, labels []string) {
	labelList := ""
	for i, label := range labels {
		if i == 0 {
			labelList += label
		} else {
			labelList += ", " + label
		}
	}
	n := fmt.Sprintf(NewDelegation, delegator, labelList, delegatee, orderNum, duration)
	notify(o, n, hipchat.YellowBackground)
}
func (o *Orderer) NotifyOrderFulfilled(name, orderNum string) {
	n := fmt.Sprintf(OrderFulfilled, name, orderNum)
	notify(o, n, hipchat.PurpleBackground)
}

// contains reports whether item is present in list.
func contains(list []string, item string) bool {
	for _, s := range list {
		if s == item {
			return true
		}
	}
	return false
}

// sameMembers reports whether a and b contain exactly the same
// elements, ignoring order.
func sameMembers(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, s := range a {
		counts[s]++
	}
	for _, s := range b {
		counts[s]--
		if counts[s] < 0 {
			return false
		}
	}
	return true
}

// binds reports whether the order is bound to the given identity: the
// target user must be one of the order's users, the given labels must
// be exactly the order's label set, and, when owner is non-empty, the
// owner must be one of the order's owners.
func (ord Order) binds(user string, labels []string, owner string) bool {
	if !contains(ord.Users, user) {
		return false
	}
	if !sameMembers(ord.Labels, labels) {
		return false
	}
	if owner != "" && !contains(ord.Owners, owner) {
		return false
	}
	return true
}

// findOrderLocked locates the outstanding order bound to the given
// identity. When orderNum is non-empty only the order with that exact
// number is considered, and it is returned only if the rest of the
// identity binds to it; a cancelled or unknown order number never
// falls back to a looser match. The caller must hold o.mu.
func (o *Orderer) findOrderLocked(user string, labels []string, owner, orderNum string) (string, bool) {
	if orderNum != "" {
		ord, ok := o.Orders[orderNum]
		if !ok || !ord.binds(user, labels, owner) {
			return "", false
		}
		return orderNum, true
	}
	for num, ord := range o.Orders {
		if ord.binds(user, labels, owner) {
			return num, true
		}
	}
	return "", false
}

// FindOrder returns the number of the outstanding order bound to the
// given identity: target user, exact label set, owner (the delegator,
// optional) and order number (optional).
func (o *Orderer) FindOrder(user string, labels []string, owner, orderNum string) (string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.findOrderLocked(user, labels, owner, orderNum)
}

// AddOrder stores a newly created order.
func (o *Orderer) AddOrder(ord Order) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.Orders[ord.Num] = ord
}

// GetOrder returns the outstanding order with the given order number.
func (o *Orderer) GetOrder(orderNum string) (Order, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	ord, ok := o.Orders[orderNum]
	return ord, ok
}

// Snapshot returns a copy of the currently outstanding orders.
func (o *Orderer) Snapshot() map[string]Order {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make(map[string]Order, len(o.Orders))
	for num, ord := range o.Orders {
		out[num] = ord
	}
	return out
}

// CancelOrder atomically removes the order with the given number, but
// only if it exists and name is the order's creator. It returns the
// removed order.
func (o *Orderer) CancelOrder(orderNum, name string) (Order, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	ord, ok := o.Orders[orderNum]
	if !ok || ord.Creator != name {
		return Order{}, false
	}
	delete(o.Orders, orderNum)
	return ord, true
}

// RecordDelegation atomically binds a delegation from owner to user to
// the outstanding order identified by the given identity and records
// the delegation against it. Owners that have already delegated are
// not counted twice. It returns the number of the order the delegation
// was recorded against.
func (o *Orderer) RecordDelegation(owner, user string, labels []string, orderNum string) (string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	num, ok := o.findOrderLocked(user, labels, owner, orderNum)
	if !ok {
		return "", false
	}
	ord := o.Orders[num]
	if !contains(ord.OwnersDelegated, owner) {
		ord.OwnersDelegated = append(ord.OwnersDelegated, owner)
		ord.Delegated++
		o.Orders[num] = ord
	}
	return num, true
}

// FulfillOrder atomically finds the outstanding order bound to the
// user and the exact label set, removes it and returns it. Orders that
// have been cancelled are no longer outstanding and can therefore
// never be fulfilled.
func (o *Orderer) FulfillOrder(user string, labels []string) (Order, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	num, ok := o.findOrderLocked(user, labels, "", "")
	if !ok {
		return Order{}, false
	}
	ord := o.Orders[num]
	delete(o.Orders, num)
	return ord, true
}
