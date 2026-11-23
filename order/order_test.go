// order_test.go: tests for the order package.
//
// Copyright (c) 2016 CloudFlare, Inc.

package order

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/redoctober/hipchat"
)

// time0 is the zero time used for test orders.
var time0 time.Time

func newTestOrderer() *Orderer {
	return NewOrderer(hipchat.HipchatClient{})
}

func newTestOrder(creator, num string, users, labels, owners []string) Order {
	return CreateOrder(creator, num, time0, 0, nil, owners, users, labels, 0)
}

func TestFindOrderBindsExactLabelSet(t *testing.T) {
	o := newTestOrderer()
	// Two overlapping orders: same target user, overlapping but
	// different label sets.
	o.AddOrder(newTestOrder("alice", "num-red", []string{"bob"}, []string{"red"}, []string{"carol"}))
	o.AddOrder(newTestOrder("alice", "num-red-blue", []string{"bob"}, []string{"red", "blue"}, []string{"carol"}))

	num, found := o.FindOrder("bob", []string{"red", "blue"}, "", "")
	if !found || num != "num-red-blue" {
		t.Fatalf("expected num-red-blue, got %q (found=%v)", num, found)
	}

	num, found = o.FindOrder("bob", []string{"blue", "red"}, "", "")
	if !found || num != "num-red-blue" {
		t.Fatalf("label set match must be order-insensitive, got %q (found=%v)", num, found)
	}

	num, found = o.FindOrder("bob", []string{"red"}, "", "")
	if !found || num != "num-red" {
		t.Fatalf("expected num-red, got %q (found=%v)", num, found)
	}

	// A superset of an order's labels must not match it.
	if _, found = o.FindOrder("bob", []string{"red", "blue", "green"}, "", ""); found {
		t.Fatal("superset of order labels must not match any order")
	}
}

func TestRecordDelegationBindsOrderNumber(t *testing.T) {
	o := newTestOrderer()
	// Two fully overlapping orders that differ only by order number.
	o.AddOrder(newTestOrder("alice", "num-1", []string{"bob"}, []string{"red"}, []string{"carol"}))
	o.AddOrder(newTestOrder("alice", "num-2", []string{"bob"}, []string{"red"}, []string{"carol"}))

	num, found := o.RecordDelegation("carol", "bob", []string{"red"}, "num-2")
	if !found || num != "num-2" {
		t.Fatalf("delegation recorded against %q, want num-2", num)
	}

	ord1, _ := o.GetOrder("num-1")
	ord2, _ := o.GetOrder("num-2")
	if ord1.Delegated != 0 || len(ord1.OwnersDelegated) != 0 {
		t.Fatalf("delegation leaked into overlapping order num-1: %+v", ord1)
	}
	if ord2.Delegated != 1 || len(ord2.OwnersDelegated) != 1 || ord2.OwnersDelegated[0] != "carol" {
		t.Fatalf("delegation not recorded against num-2: %+v", ord2)
	}

	// A delegation for an unknown (or already cancelled) order number
	// must not fall back to an overlapping order.
	if _, found := o.RecordDelegation("carol", "bob", []string{"red"}, "num-gone"); found {
		t.Fatal("delegation for unknown order number must not be recorded")
	}
	if ord1, _ = o.GetOrder("num-1"); ord1.Delegated != 0 {
		t.Fatalf("delegation for unknown order leaked into num-1: %+v", ord1)
	}
}

func TestRecordDelegationBindsOwner(t *testing.T) {
	o := newTestOrderer()
	o.AddOrder(newTestOrder("alice", "num-1", []string{"bob"}, []string{"red"}, []string{"carol"}))

	// dave is not an owner of the order's ciphertext.
	if _, found := o.RecordDelegation("dave", "bob", []string{"red"}, ""); found {
		t.Fatal("delegation from non-owner must not be recorded")
	}
	if _, found := o.RecordDelegation("carol", "bob", []string{"red"}, ""); !found {
		t.Fatal("delegation from owner must be recorded")
	}

	// The same owner delegating twice is only counted once.
	if _, found := o.RecordDelegation("carol", "bob", []string{"red"}, ""); !found {
		t.Fatal("repeat delegation from owner must still match the order")
	}
	ord, _ := o.GetOrder("num-1")
	if ord.Delegated != 1 || len(ord.OwnersDelegated) != 1 {
		t.Fatalf("owner counted twice: %+v", ord)
	}
}

func TestCancelledOrderCannotBeFulfilled(t *testing.T) {
	o := newTestOrderer()
	o.AddOrder(newTestOrder("alice", "num-1", []string{"bob"}, []string{"red"}, []string{"carol"}))

	// Only the creator can cancel the order.
	if _, ok := o.CancelOrder("num-1", "mallory"); ok {
		t.Fatal("non-creator must not be able to cancel the order")
	}
	if _, ok := o.GetOrder("num-1"); !ok {
		t.Fatal("order must still be outstanding after failed cancel")
	}

	if _, ok := o.CancelOrder("num-1", "alice"); !ok {
		t.Fatal("creator must be able to cancel the order")
	}

	// After cancellation the order can neither be fulfilled nor
	// receive further delegations.
	if _, found := o.FulfillOrder("bob", []string{"red"}); found {
		t.Fatal("cancelled order must not be fulfilled")
	}
	if _, found := o.RecordDelegation("carol", "bob", []string{"red"}, "num-1"); found {
		t.Fatal("cancelled order must not absorb delegations")
	}
}

func TestFulfillOrderRemovesExactlyOneOrder(t *testing.T) {
	o := newTestOrderer()
	o.AddOrder(newTestOrder("alice", "num-1", []string{"bob"}, []string{"red"}, []string{"carol"}))
	o.AddOrder(newTestOrder("alice", "num-2", []string{"bob"}, []string{"red", "blue"}, []string{"carol"}))

	// Fulfilling with labels {red, blue} must not touch the {red} order.
	ord, found := o.FulfillOrder("bob", []string{"blue", "red"})
	if !found || ord.Num != "num-2" {
		t.Fatalf("fulfilled %q, want num-2", ord.Num)
	}
	if _, ok := o.GetOrder("num-1"); !ok {
		t.Fatal("overlapping order num-1 must remain outstanding")
	}
	if _, found := o.FulfillOrder("bob", []string{"blue", "red"}); found {
		t.Fatal("order must not be fulfilled twice")
	}
}

// TestConcurrentOverlappingOrders hammers an Orderer with concurrent
// creations, delegations, fulfillments and cancellations of
// overlapping orders. Run with -race. Afterwards the state must be
// consistent: every outstanding order's delegation count matches its
// recorded owners, no delegation was recorded from a non-owner, and no
// order was both cancelled and fulfilled.
func TestConcurrentOverlappingOrders(t *testing.T) {
	o := newTestOrderer()
	const creators = 4
	const ordersPerCreator = 5

	var wg sync.WaitGroup

	// Bookkeeping for the outcomes observed by the worker goroutines.
	var mu sync.Mutex
	cancelled := map[string]bool{}
	fulfilled := map[string]bool{}

	// Creators concurrently place overlapping orders: all of them
	// target the same user with the same label set, so only the order
	// number (and creator/owner binding) tells them apart.
	for c := 0; c < creators; c++ {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			creator := fmt.Sprintf("creator-%d", c)
			for i := 0; i < ordersPerCreator; i++ {
				num := fmt.Sprintf("num-%d-%d", c, i)
				o.AddOrder(newTestOrder(creator, num, []string{"bob"}, []string{"red", "blue"},
					[]string{fmt.Sprintf("owner-%d", c)}))
			}
		}()
	}
	wg.Wait()

	// Owners concurrently delegate against their own creator's orders,
	// using explicit order numbers. A delegation may legitimately fail
	// when it races a cancellation or fulfillment of the same order,
	// but it must never be recorded against a different order.
	for c := 0; c < creators; c++ {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			owner := fmt.Sprintf("owner-%d", c)
			for i := 0; i < ordersPerCreator; i++ {
				num := fmt.Sprintf("num-%d-%d", c, i)
				if got, found := o.RecordDelegation(owner, "bob", []string{"red", "blue"}, num); found && got != num {
					t.Errorf("delegation for %q recorded against %q", num, got)
				}
			}
		}()
	}

	// Concurrently, creators cancel their even-numbered orders and
	// fulfillments race against everything.
	for c := 0; c < creators; c++ {
		c := c
		wg.Add(2)
		go func() {
			defer wg.Done()
			creator := fmt.Sprintf("creator-%d", c)
			for i := 0; i < ordersPerCreator; i += 2 {
				num := fmt.Sprintf("num-%d-%d", c, i)
				if _, ok := o.CancelOrder(num, creator); ok {
					mu.Lock()
					cancelled[num] = true
					mu.Unlock()
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < ordersPerCreator; i++ {
				if ord, found := o.FulfillOrder("bob", []string{"red", "blue"}); found {
					mu.Lock()
					fulfilled[ord.Num] = true
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	outstanding := o.Snapshot()

	// A cancelled order can never be fulfilled afterwards, and neither
	// a cancelled nor a fulfilled order may remain outstanding.
	for num := range cancelled {
		if fulfilled[num] {
			t.Errorf("order %q was fulfilled after being cancelled", num)
		}
		if _, ok := outstanding[num]; ok {
			t.Errorf("cancelled order %q still outstanding", num)
		}
	}
	for num := range fulfilled {
		if _, ok := outstanding[num]; ok {
			t.Errorf("fulfilled order %q still outstanding", num)
		}
	}

	// Whatever remains outstanding must be internally consistent.
	for num, ord := range outstanding {
		if ord.Num != num {
			t.Errorf("order %q stored under key %q", ord.Num, num)
		}
		if ord.Delegated != len(ord.OwnersDelegated) {
			t.Errorf("order %q: Delegated=%d but %d owners recorded", num, ord.Delegated, len(ord.OwnersDelegated))
		}
		for _, owner := range ord.OwnersDelegated {
			if !contains(ord.Owners, owner) {
				t.Errorf("order %q: delegation recorded from non-owner %q", num, owner)
			}
		}
	}
}

// TestNotificationFormats pins the legacy notification wording.
func TestNotificationFormats(t *testing.T) {
	if NewOrder != "%s has created an order for the label %s. requesting %d delegations for %s" {
		t.Errorf("NewOrder format changed: %q", NewOrder)
	}
	if NewOrderLink != "@%s - https://%s?%s" {
		t.Errorf("NewOrderLink format changed: %q", NewOrderLink)
	}
	if OrderFulfilled != "%s has had order %s fulfilled." {
		t.Errorf("OrderFulfilled format changed: %q", OrderFulfilled)
	}
	if NewDelegation != "%s has delegated the label %s to %s (per order %s) for %s" {
		t.Errorf("NewDelegation format changed: %q", NewDelegation)
	}
}
