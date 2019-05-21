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
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/aliasservergo"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/bcnetgo"
	"github.com/AletheiaWareLLC/financego"
	"github.com/AletheiaWareLLC/spacego"
	"github.com/golang/protobuf/proto"
	"html/template"
	"log"
	"math"
	"net/http"
	"os"
	"path"
	"time"
)

func main() {
	rootDir, err := bcgo.GetRootDirectory()
	if err != nil {
		log.Println(err)
		return
	}
	//log.Println("Root Dir:", rootDir)

	logFile, err := bcgo.SetupLogging(rootDir)
	if err != nil {
		log.Println(err)
		return
	}
	defer logFile.Close()
	//log.Println("Log File:", logFile.Name())

	cacheDir, err := bcgo.GetCacheDirectory(rootDir)
	if err != nil {
		log.Println(err)
		return
	}
	//log.Println("Cache Dir:", cacheDir)

	cache, err := bcgo.NewFileCache(cacheDir)
	if err != nil {
		log.Println(err)
		return
	}

	network := &bcgo.TcpNetwork{}

	node, err := bcgo.GetNode(rootDir, cache, network)
	if err != nil {
		log.Println(err)
		return
	}

	aliases := aliasgo.OpenAndLoadAliasChannel(cache, network)
	node.AddChannel(aliases)
	customers := financego.OpenAndLoadCustomerChannel(cache, network)
	node.AddChannel(customers)
	subscriptions := financego.OpenAndLoadSubscriptionChannel(cache, network)
	node.AddChannel(subscriptions)

	listener := &bcgo.PrintingMiningListener{os.Stdout}

	// Serve Block Requests
	go bcnetgo.Bind(bcgo.PORT_GET_BLOCK, bcnetgo.BlockPortHandler(cache, network))
	// Serve Head Requests
	go bcnetgo.Bind(bcgo.PORT_GET_HEAD, bcnetgo.HeadPortHandler(cache, network))
	// Serve Block Updates
	go bcnetgo.Bind(bcgo.PORT_BROADCAST, bcnetgo.BroadcastPortHandler(cache, network, func(name string) (bcgo.Channel, error) {
		return node.GetChannel(name)
	}))

	// Redirect HTTP Requests to HTTPS
	go http.ListenAndServe(":80", http.HandlerFunc(bcnetgo.HTTPSRedirect))

	// Serve Web Requests
	mux := http.NewServeMux()
	mux.HandleFunc("/", bcnetgo.StaticHandler)
	aliasTemplate, err := template.ParseFiles("html/template/alias.html")
	if err != nil {
		log.Println(err)
		return
	}
	mux.HandleFunc("/alias", aliasservergo.AliasHandler(aliases, cache, network, aliasTemplate))
	aliasRegistrationTemplate, err := template.ParseFiles("html/template/alias-register.html")
	if err != nil {
		log.Println(err)
		return
	}
	mux.HandleFunc("/alias-register", aliasservergo.AliasRegistrationHandler(node, listener, aliasRegistrationTemplate))
	blockTemplate, err := template.ParseFiles("html/template/block.html")
	if err != nil {
		log.Println(err)
		return
	}
	mux.HandleFunc("/block", bcnetgo.BlockHandler(cache, network, blockTemplate))
	channelTemplate, err := template.ParseFiles("html/template/channel.html")
	if err != nil {
		log.Println(err)
		return
	}
	mux.HandleFunc("/channel", bcnetgo.ChannelHandler(cache, network, channelTemplate))
	channelListTemplate, err := template.ParseFiles("html/template/channel-list.html")
	if err != nil {
		log.Println(err)
		return
	}
	mux.HandleFunc("/channels", bcnetgo.ChannelListHandler(cache, network, channelListTemplate, node.GetChannels))
	mux.HandleFunc("/keys", bcnetgo.KeyShareHandler(make(bcnetgo.KeyShareStore), 2*time.Minute))
	mux.HandleFunc("/mining/file", MiningHandler(node, func(record *bcgo.Record) string {
		// Space-File-<creator-alias>
		return spacego.SPACE_PREFIX_FILE + record.Creator
	}))
	mux.HandleFunc("/mining/meta", MiningHandler(node, func(record *bcgo.Record) string {
		// Space-Meta-<creator-alias>
		return spacego.SPACE_PREFIX_META + record.Creator
	}))
	mux.HandleFunc("/mining/share", MiningHandler(node, func(record *bcgo.Record) string {
		// Space-Share-<receiver-alias>
		if len(record.Access) == 0 {
			// TODO share publicly
		} else {
			// Receiver alias is first access which is not creator
			for _, a := range record.Access {
				if a.Alias != record.Creator {
					return spacego.SPACE_PREFIX_SHARE + a.Alias
				}
			}
		}
		return ""
	}))
	mux.HandleFunc("/mining/preview", MiningHandler(node, func(record *bcgo.Record) string {
		// Space-Preview-<meta-record-hash>
		return spacego.SPACE_PREFIX_PREVIEW + base64.RawURLEncoding.EncodeToString(record.Reference[0].RecordHash) // TODO handle all References
	}))
	mux.HandleFunc("/mining/tag", MiningHandler(node, func(record *bcgo.Record) string {
		// Space-Tag-<meta-record-hash>
		return spacego.SPACE_PREFIX_TAG + base64.RawURLEncoding.EncodeToString(record.Reference[0].RecordHash) // TODO handle all References
	}))
	mux.HandleFunc("/stripe-webhook", bcnetgo.StripeWebhookHandler)
	registrationTemplate, err := template.ParseFiles("html/template/space-register.html")
	if err != nil {
		log.Println(err)
		return
	}
	publishableKey := os.Getenv("STRIPE_PUBLISHABLE_KEY")
	mux.HandleFunc("/space-register", bcnetgo.RegistrationHandler(node, listener, registrationTemplate, publishableKey))
	subscriptionTemplate, err := template.ParseFiles("html/template/space-subscribe.html")
	if err != nil {
		log.Println(err)
		return
	}
	productId := os.Getenv("STRIPE_PRODUCT_ID")
	planId := os.Getenv("STRIPE_PLAN_ID")
	mux.HandleFunc("/space-subscribe", bcnetgo.SubscriptionHandler(node, listener, subscriptionTemplate, productId, planId))
	certDir, err := bcgo.GetCertificateDirectory(rootDir)
	if err != nil {
		log.Println(err)
		return
	}
	// Serve HTTPS Requests
	log.Println(http.ListenAndServeTLS(":443", path.Join(certDir, "fullchain.pem"), path.Join(certDir, "privkey.pem"), mux))
}

func MiningHandler(node *bcgo.Node, getChannelName func(*bcgo.Record) string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RemoteAddr, r.Proto, r.Method, r.Host, r.URL.Path)
		log.Println(r.Header)
		switch r.Method {
		case "POST":
			record := &bcgo.Record{}
			if err := bcgo.ReadDelimitedProtobuf(bufio.NewReader(r.Body), record); err != nil {
				log.Println(err)
				return
			}

			size := proto.Size(record)
			log.Println("Record", size, record.Creator)

			aliases, err := node.GetChannel(aliasgo.ALIAS)
			if err != nil {
				log.Println(err)
				return
			}
			// Get rsa.PublicKey for Alias
			publicKey, err := aliasgo.GetPublicKey(aliases, node.Cache, node.Network, record.Creator)
			if err != nil {
				log.Println(err)
				return
			}

			// Verify Signature
			if err := bcgo.VerifySignature(publicKey, bcgo.Hash(record.Payload), record.Signature, record.SignatureAlgorithm); err != nil {
				log.Println("Signature Verification Failed", err)
				return
			}

			// Get Customer for Alias
			customers, err := node.GetChannel(financego.CUSTOMER)
			if err != nil {
				log.Println(err)
				return
			}
			customer, err := financego.GetCustomerSync(customers, node.Cache, node.Alias, node.Key, record.Creator)
			if err != nil {
				log.Println(err)
				return
			}
			if customer == nil {
				log.Println(errors.New(record.Creator + " is not a customer"))
				return
			}

			// Get Subscription for Alias
			subscriptions, err := node.GetChannel(financego.SUBSCRIPTION)
			if err != nil {
				log.Println(err)
				return
			}
			subscription, err := financego.GetSubscriptionSync(subscriptions, node.Cache, node.Alias, node.Key, record.Creator)
			if err != nil {
				log.Println(err)
				return
			}
			if subscription == nil {
				// Divide bytes by 1000000 = $0.01 per Mb
				amount := int64(math.Ceil(float64(size) / 1000000.0))
				// Charge Customer
				stripeCharge, bcCharge, err := financego.NewCustomerCharge(customer, amount, fmt.Sprintf("Space Remote Mining Charge %dbytes", size))
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
				stripeUsageRecord, bcUsageRecord, err := financego.NewUsageRecord(record.Creator, subscription.SubscriptionItemId, time.Now().Unix(), int64(size))
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("UsageRecord", stripeUsageRecord)
				log.Println("UsageRecord", bcUsageRecord)
				// TODO Mine bcUsageRecord into UsageChannel
			}

			// Lookup Channel
			channel := bcgo.OpenAndLoadPoWChannel(getChannelName(record), bcgo.THRESHOLD_STANDARD, node.Cache, node.Network)
			if channel == nil {
				log.Println("Could not get channel for record: " + record.String())
				return
			}

			// Write record to cache
			reference, err := bcgo.WriteRecord(channel.GetName(), node.Cache, record)
			if err != nil {
				log.Println(err)
				return
			}

			// Mine channel in goroutine
			go func(c *bcgo.PoWChannel) {
				_, _, err = node.Mine(c, nil)
				if err != nil {
					log.Println(err)
					return
				}
			}(channel)

			// Reply with reference
			log.Println("Reference", reference)
			if err := bcgo.WriteDelimitedProtobuf(bufio.NewWriter(w), reference); err != nil {
				log.Println(err)
				return
			}
		default:
			log.Println("Unsupported method", r.Method)
		}
	}
}
