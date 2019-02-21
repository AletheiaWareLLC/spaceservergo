/*
 * Copyright 2019 Aletheia Ware LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bufio"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/bcnetgo"
	"github.com/AletheiaWareLLC/financego"
	"github.com/AletheiaWareLLC/spacego"
	"github.com/golang/protobuf/proto"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"time"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	// Serve Block Requests
	go bcnetgo.Bind(bcgo.PORT_BLOCK, bcnetgo.HandleBlock)
	// Serve Head Requests
	go bcnetgo.Bind(bcgo.PORT_HEAD, bcnetgo.HandleHead)
	// Serve Block Updates
	go bcnetgo.Bind(bcgo.PORT_CAST, bcnetgo.HandleCast)

	// Serve Web Requests
	mux := http.NewServeMux()
	mux.HandleFunc("/", bcnetgo.HandleStatic)
	mux.HandleFunc("/alias", bcnetgo.HandleAlias)
	mux.HandleFunc("/mining/file", CreateMiningHandler(func(record *bcgo.Record) (*bcgo.Channel, error) {
		// Space-File-<creator-alias>
		return bcgo.OpenChannel(spacego.SPACE_PREFIX_FILE + record.Creator)
	}))
	mux.HandleFunc("/mining/meta", CreateMiningHandler(func(record *bcgo.Record) (*bcgo.Channel, error) {
		// Space-Meta-<creator-alias>
		return bcgo.OpenChannel(spacego.SPACE_PREFIX_META + record.Creator)
	}))
	mux.HandleFunc("/mining/share", CreateMiningHandler(func(record *bcgo.Record) (*bcgo.Channel, error) {
		// Space-Share-<receiver-alias>
		return bcgo.OpenChannel(spacego.SPACE_PREFIX_SHARE + record.Access[0].Alias) // TODO handle all Accesses
	}))
	mux.HandleFunc("/mining/preview", CreateMiningHandler(func(record *bcgo.Record) (*bcgo.Channel, error) {
		// Space-Preview-<meta-record-hash>
		return bcgo.OpenChannel(spacego.SPACE_PREFIX_PREVIEW + base64.RawURLEncoding.EncodeToString(record.Reference[0].RecordHash)) // TODO handle all References
	}))
	mux.HandleFunc("/mining/tag", CreateMiningHandler(func(record *bcgo.Record) (*bcgo.Channel, error) {
		// Space-Tag-<meta-record-hash>
		return bcgo.OpenChannel(spacego.SPACE_PREFIX_TAG + base64.RawURLEncoding.EncodeToString(record.Reference[0].RecordHash)) // TODO handle all References
	}))
	mux.HandleFunc("/stripe-webhook", HandleStripeWebhook)
	// TODO mux.HandleFunc("/registration", HandleRegister)
	mux.HandleFunc("/subscription", HandleSubscribe)
	store, err := bcnetgo.GetSecurityStore()
	if err != nil {
		log.Println(err)
		return
	}
	// Serve HTTPS Requests
	log.Fatal(http.ListenAndServeTLS(":443", path.Join(store, "fullchain.pem"), path.Join(store, "privkey.pem"), mux))

	// TODO Redirect HTTP Requests to HTTPS
	// log.Fatal(http.ListenAndServe(":80", http.HandlerFunc(bcnetgo.HTTPSRedirect)))
}

func HandleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	log.Println(r.RemoteAddr, r.Proto, r.Method, r.Host, r.URL.Path)
	log.Println("Stripe Webhook", r)
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		return
	}
	event, err := financego.ConstructEvent(data, r.Header.Get("Stripe-Signature"))
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("Event", event)
	w.WriteHeader(http.StatusOK)
}

// TODO split into HandleRegister for creating Customer, and HandleSubscribe for creating Subscription
func HandleSubscribe(w http.ResponseWriter, r *http.Request) {
	log.Println(r.RemoteAddr, r.Proto, r.Method, r.Host, r.URL.Path)
	switch r.Method {
	case "GET":
		query := r.URL.Query()
		var a string
		if results, ok := query["alias"]; ok && len(results) == 1 {
			a = results[0]
		}
		log.Println("Alias", a)
		var publicKey string
		if results, ok := query["publicKey"]; ok && len(results) == 1 {
			publicKey = results[0]
		}
		log.Println("PublicKey", publicKey)
		t, err := template.ParseFiles("html/template/subscription.html")
		if err != nil {
			log.Println(err)
			return
		}
		data := struct {
			Description string
			Key         string
			Name        string
			Alias       string
			PublicKey   string
		}{
			Description: "Remote Mining Service",
			Key:         os.Getenv("STRIPE_PUBLISHABLE_KEY"),
			Name:        "Aletheia Ware LLC",
			Alias:       a,
			PublicKey:   publicKey,
		}
		log.Println("Data", data)
		err = t.Execute(w, data)
		if err != nil {
			log.Println(err)
			return
		}
	case "POST":
		r.ParseForm()
		a := r.Form["alias"]
		stripeEmail := r.Form["stripeEmail"]
		// stripeBillingName := r.Form["stripeBillingName"]
		// stripeBillingAddressLine1 := r.Form["stripeBillingAddressLine1"]
		// stripeBillingAddressCity := r.Form["stripeBillingAddressCity"]
		// stripeBillingAddressZip := r.Form["stripeBillingAddressZip"]
		// stripeBillingAddressCountry := r.Form["stripeBillingAddressCountry"]
		// stripeBillingAddressCountryCode := r.Form["stripeBillingAddressCountryCode"]
		// stripeBillingAddressState := r.Form["stripeBillingAddressState"]
		stripeToken := r.Form["stripeToken"]
		// stripeTokenType := r.Form["stripeTokenType"]

		if len(a) > 0 && len(stripeEmail) > 0 && len(stripeToken) > 0 {
			node, err := bcgo.GetNode()
			if err != nil {
				log.Println(err)
				return
			}

			aliases, err := aliasgo.OpenAliasChannel()
			if err != nil {
				log.Println(err)
				return
			}

			if err := aliases.Sync(); err != nil {
				log.Println(err)
				return
			}
			// Get rsa.PublicKey for Alias
			publicKey, err := aliasgo.GetPublicKey(aliases, a[0])
			if err != nil {
				log.Println(err)
				return
			}

			// Create list of access (user + server)
			acl := map[string]*rsa.PublicKey{
				a[0]:       publicKey,
				node.Alias: &node.Key.PublicKey,
			}
			log.Println("Access", acl)

			stripeCustomer, bcCustomer, err := financego.NewCustomer(a[0], stripeEmail[0], stripeToken[0], "Aletheia Ware LLC Mining Service Customer")
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("StripeCustomer", stripeCustomer)
			log.Println("BcCustomer", bcCustomer)
			customerData, err := proto.Marshal(bcCustomer)
			if err != nil {
				log.Println(err)
				return
			}

			customers, err := financego.OpenCustomerChannel()
			if err != nil {
				log.Println(err)
				return
			}

			customerReference, err := node.Mine(customers, acl, nil, customerData)
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("CustomerReference", customerReference)

			productId := os.Getenv("STRIPE_PRODUCT_ID")
			planId := os.Getenv("STRIPE_PLAN_ID")

			stripeSubscription, bcSubscription, err := financego.NewSubscription(a[0], stripeCustomer.ID, "", productId, planId)
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("StripeSubscription", stripeSubscription)
			log.Println("BcSubscription", bcSubscription)

			subscriptionData, err := proto.Marshal(bcSubscription)
			if err != nil {
				log.Println(err)
				return
			}

			subscriptions, err := financego.OpenSubscriptionChannel()
			if err != nil {
				log.Println(err)
				return
			}

			references := []*bcgo.Reference{customerReference}

			subscriptionReference, err := node.Mine(subscriptions, acl, references, subscriptionData)
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("SubscriptionReference", subscriptionReference)

			http.Redirect(w, r, "/success.html", http.StatusFound)
		}
	default:
		log.Println("Unsupported method", r.Method)
	}
}

func CreateMiningHandler(lookup func(*bcgo.Record) (*bcgo.Channel, error)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RemoteAddr, r.Proto, r.Method, r.Host, r.URL.Path)
		switch r.Method {
		case "POST":
			request, err := bcgo.ReadRecord(bufio.NewReader(r.Body))
			if err != nil {
				log.Println(err)
				return
			}

			size := proto.Size(request)
			log.Println("Record", size, request.Creator)

			node, err := bcgo.GetNode()
			if err != nil {
				log.Println(err)
				return
			}

			aliases, err := aliasgo.OpenAliasChannel()
			if err != nil {
				log.Println(err)
				return
			}

			// Get rsa.PublicKey for Alias
			publicKey, err := aliasgo.GetPublicKey(aliases, request.Creator)
			if err != nil {
				log.Println(err)
				return
			}

			// Verify Signature
			if err := bcgo.VerifySignature(publicKey, bcgo.Hash(request.Payload), request.Signature, request.SignatureAlgorithm); err != nil {
				log.Println("Signature Verification Failed", err)
				return
			}

			customers, err := financego.OpenCustomerChannel()
			if err != nil {
				log.Println(err)
				return
			}

			// Get Customer for Alias
			customer, err := financego.GetCustomerSync(customers, node.Alias, node.Key, request.Creator)
			if err != nil {
				log.Println(err)
				return
			}

			subscriptions, err := financego.OpenSubscriptionChannel()
			if err != nil {
				log.Println(err)
				return
			}

			// Get Subscription for Alias
			subscription, err := financego.GetSubscriptionSync(subscriptions, node.Alias, node.Key, request.Creator)
			if err != nil {
				// Charge Customer
				stripeCharge, bcCharge, err := financego.NewCustomerCharge(customer, int64(size), fmt.Sprintf("Aletheia Ware LLC Mining Charge %dbytes", size))
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Charge", stripeCharge)
				log.Println("Charge", bcCharge)
				// TODO Mine bcCharge into ChargeChannel
			} else {
				// Log Subscription Usage
				if customer.CustomerId != subscription.CustomerId {
					log.Println("Customer ID doesn't match Subscription Customer ID")
					return
				}
				stripeUsageRecord, bcUsageRecord, err := financego.NewUsageRecord(request.Creator, subscription.SubscriptionItemId, time.Now().Unix(), int64(size))
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("UsageRecord", stripeUsageRecord)
				log.Println("UsageRecord", bcUsageRecord)
				// TODO Mine bcUsageRecord into UsageChannel
			}

			// Lookup Channel
			channel, err := lookup(request)
			if err != nil {
				log.Println(err)
				return
			}

			// Marshal into byte array
			data, err := proto.Marshal(request)
			if err != nil {
				log.Println(err)
				return
			}

			// Get record hash
			hash := bcgo.Hash(data)

			// Create entry array containing hash and record
			entries := [1]*bcgo.BlockEntry{
				&bcgo.BlockEntry{
					RecordHash: hash,
					Record:     request,
				},
			}

			// Mine channel in goroutine
			go func(c *bcgo.Channel, es []*bcgo.BlockEntry) {
				_, _, err := node.MineRecords(c, es)
				if err != nil {
					log.Println(err)
					return
				}
			}(channel, entries[:])

			// Return reference to record
			response := &bcgo.Reference{
				Timestamp:   request.Timestamp,
				ChannelName: channel.Name,
				RecordHash:  hash,
			}

			// Reply with reference
			log.Println("Reference", response)
			if err := bcgo.WriteReference(bufio.NewWriter(w), response); err != nil {
				log.Println(err)
				return
			}
		default:
			log.Println("Unsupported method", r.Method)
		}
	}
}
