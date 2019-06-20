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
	"strings"
	"time"
)

func main() {
	rootDir, err := bcgo.GetRootDirectory()
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Root Directory:", rootDir)

	certDir, err := bcgo.GetCertificateDirectory(rootDir)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Certificate Directory:", certDir)

	logFile, err := bcgo.SetupLogging(rootDir)
	if err != nil {
		log.Println(err)
		return
	}
	defer logFile.Close()
	log.Println("Log File:", logFile.Name())

	cacheDir, err := bcgo.GetCacheDirectory(rootDir)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Cache Directory:", cacheDir)

	cache, err := bcgo.NewFileCache(cacheDir)
	if err != nil {
		log.Println(err)
		return
	}

	peers, err := bcgo.GetPeers(rootDir)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Peers:", peers)

	network := &bcgo.TcpNetwork{
		Peers: peers,
	}

	node, err := bcgo.GetNode(rootDir, cache, network)
	if err != nil {
		log.Println(err)
		return
	}

	aliases := aliasgo.OpenAliasChannel()
	if err := bcgo.LoadHead(aliases, cache, network); err != nil {
		log.Println(err)
	}
	if err := bcgo.Pull(aliases, cache, network); err != nil {
		log.Println(err)
	}
	node.AddChannel(aliases)

	registrations := financego.OpenRegistrationChannel()
	if err := bcgo.LoadHead(registrations, cache, network); err != nil {
		log.Println(err)
	}
	if err := bcgo.Pull(registrations, cache, network); err != nil {
		log.Println(err)
	}
	node.AddChannel(registrations)

	subscriptions := financego.OpenSubscriptionChannel()
	if err := bcgo.LoadHead(subscriptions, cache, network); err != nil {
		log.Println(err)
	}
	if err := bcgo.Pull(subscriptions, cache, network); err != nil {
		log.Println(err)
	}
	node.AddChannel(subscriptions)

	listener := &bcgo.PrintingMiningListener{os.Stdout}

	// Serve Block Requests
	go bcnetgo.Bind(bcgo.PORT_GET_BLOCK, bcnetgo.BlockPortHandler(cache, network))
	// Serve Head Requests
	go bcnetgo.Bind(bcgo.PORT_GET_HEAD, bcnetgo.HeadPortHandler(cache, network))
	// Serve Block Updates
	go bcnetgo.Bind(bcgo.PORT_BROADCAST, bcnetgo.BroadcastPortHandler(cache, network, func(name string) (bcgo.Channel, error) {
		channel, err := node.GetChannel(name)
		if err != nil {
			if strings.HasPrefix(name, spacego.SPACE_PREFIX) {
				channel = bcgo.OpenPoWChannel(name, bcgo.THRESHOLD_STANDARD)
				if err := bcgo.LoadHead(channel, node.Cache, node.Network); err != nil {
					log.Println(err)
				}
				if err := bcgo.Pull(channel, node.Cache, node.Network); err != nil {
					log.Println(err)
				}
				node.AddChannel(channel)
			} else {
				return nil, err
			}
		}
		return channel, nil
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
	mux.HandleFunc("/alias-register", aliasservergo.AliasRegistrationHandler(aliases, node, listener, aliasRegistrationTemplate))
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
	storageProductId := os.Getenv("STRIPE_STORAGE_PRODUCT_ID")
	storagePlanId := os.Getenv("STRIPE_STORAGE_PLAN_ID")
	miningProductId := os.Getenv("STRIPE_MINING_PRODUCT_ID")
	miningPlanId := os.Getenv("STRIPE_MINING_PLAN_ID")
	mux.HandleFunc("/mining/file", MiningHandler(aliases, node, miningProductId, miningPlanId, func(record *bcgo.Record) string {
		// Space-File-<creator-alias>
		return spacego.SPACE_PREFIX_FILE + record.Creator
	}))
	mux.HandleFunc("/mining/meta", MiningHandler(aliases, node, miningProductId, miningPlanId, func(record *bcgo.Record) string {
		// Space-Meta-<creator-alias>
		return spacego.SPACE_PREFIX_META + record.Creator
	}))
	mux.HandleFunc("/mining/share", MiningHandler(aliases, node, miningProductId, miningPlanId, func(record *bcgo.Record) string {
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
	mux.HandleFunc("/mining/preview", MiningHandler(aliases, node, miningProductId, miningPlanId, func(record *bcgo.Record) string {
		// Space-Preview-<meta-record-hash>
		return spacego.SPACE_PREFIX_PREVIEW + base64.RawURLEncoding.EncodeToString(record.Reference[0].RecordHash) // TODO handle all References
	}))
	mux.HandleFunc("/mining/tag", MiningHandler(aliases, node, miningProductId, miningPlanId, func(record *bcgo.Record) string {
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
	mux.HandleFunc("/space-register", bcnetgo.RegistrationHandler(aliases, node, listener, registrationTemplate, publishableKey))
	subscriptionTemplate, err := template.ParseFiles("html/template/space-storage-subscribe.html")
	if err != nil {
		log.Println(err)
		return
	}
	mux.HandleFunc("/space-storage-subscribe", bcnetgo.SubscriptionHandler(aliases, node, listener, subscriptionTemplate, storageProductId, storagePlanId))
	subscriptionTemplate, err = template.ParseFiles("html/template/space-mining-subscribe.html")
	if err != nil {
		log.Println(err)
		return
	}
	mux.HandleFunc("/space-mining-subscribe", bcnetgo.SubscriptionHandler(aliases, node, listener, subscriptionTemplate, miningProductId, miningPlanId))
	// Periodically measure storage usage per customer
	ticker := time.NewTicker(5 * 24 * time.Hour) // Every 5 days
	quiter := make(chan struct{})
	defer close(quiter)
	go func() {
		for {
			select {
			case <-ticker.C:
				if err := MeasureStorageUsage(node, cache, storageProductId, storagePlanId); err != nil {
					log.Println(err)
					return
				}
			case <-quiter:
				ticker.Stop()
				return
			}
		}
	}()
	// Serve HTTPS Requests
	log.Println(http.ListenAndServeTLS(":443", path.Join(certDir, "fullchain.pem"), path.Join(certDir, "privkey.pem"), mux))
}

func MiningHandler(aliases *aliasgo.AliasChannel, node *bcgo.Node, productId, planId string, getChannelName func(*bcgo.Record) string) func(http.ResponseWriter, *http.Request) {
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
			log.Println("Record", record.Creator, size)

			// Get Channel
			name := getChannelName(record)
			log.Println("Channel", name)
			if name == "" {
				log.Println("Could not get channel name from record")
				return
			}
			channel, err := node.GetChannel(name)
			if err != nil {
				if strings.HasPrefix(name, spacego.SPACE_PREFIX) {
					channel = bcgo.OpenPoWChannel(name, bcgo.THRESHOLD_STANDARD)
					if err := bcgo.LoadHead(channel, node.Cache, node.Network); err != nil {
						log.Println(err)
					}
					if err := bcgo.Pull(channel, node.Cache, node.Network); err != nil {
						log.Println(err)
					}
					node.AddChannel(channel)
				} else {
					log.Println(err)
					return
				}
			}

			if err := bcgo.Pull(aliases, node.Cache, node.Network); err != nil {
				log.Println(err)
			}

			// Get rsa.PublicKey for Alias
			publicKey, err := aliases.GetPublicKey(node.Cache, node.Network, record.Creator)
			if err != nil {
				log.Println(err)
				return
			}

			// Verify Signature
			if err := bcgo.VerifySignature(publicKey, bcgo.Hash(record.Payload), record.Signature, record.SignatureAlgorithm); err != nil {
				log.Println("Signature Verification Failed", err)
				return
			}

			// Get Registration for Alias
			registrations, err := node.GetChannel(financego.REGISTRATION)
			if err != nil {
				log.Println(err)
				return
			}
			registration, err := financego.GetRegistrationSync(registrations, node.Cache, node.Network, node.Alias, node.Key, record.Creator, nil)
			if err != nil {
				log.Println(err)
				return
			}
			if registration == nil {
				log.Println(errors.New(record.Creator + " is not registered"))
				return
			}

			// Get Subscription for Alias
			subscriptions, err := node.GetChannel(financego.SUBSCRIPTION)
			if err != nil {
				log.Println(err)
				return
			}
			subscription, err := financego.GetSubscriptionSync(subscriptions, node.Cache, node.Network, node.Alias, node.Key, record.Creator, nil, productId, planId)
			if err != nil {
				log.Println(err)
				return
			}
			if subscription == nil {
				// Divide bytes by 1000000 = $0.01 per Mb
				amount := int64(math.Ceil(float64(size) / 1000000.0))
				// Charge Customer
				stripeCharge, bcCharge, err := financego.NewCustomerCharge(registration, amount, fmt.Sprintf("Space Remote Mining Charge %dbytes", size))
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Charge", stripeCharge)
				log.Println("Charge", bcCharge)
				// TODO Mine bcCharge into ChargeChannel
			} else {
				// Log Subscription Usage
				if registration.CustomerId != subscription.CustomerId {
					log.Println("Registration Customer ID doesn't match Subscription Customer ID")
					return
				}
				stripeUsageRecord, bcUsageRecord, err := financego.NewUsageRecord(node.Alias, record.Creator, subscription.SubscriptionItemId, time.Now().Unix(), int64(size))
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("UsageRecord", stripeUsageRecord)
				log.Println("UsageRecord", bcUsageRecord)
				// TODO Mine bcUsageRecord into UsageChannel
			}

			// Write record to cache
			reference, err := bcgo.WriteRecord(name, node.Cache, record)
			if err != nil {
				log.Println(err)
				return
			}

			// Mine channel in goroutine
			go func(c bcgo.ThresholdChannel) {
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

func MeasureStorageUsage(node *bcgo.Node, cache *bcgo.FileCache, productId, planId string) error {
	usage, err := cache.MeasureStorageUsage(spacego.SPACE_PREFIX)
	if err != nil {
		return err
	}
	registrations, err := node.GetChannel(financego.REGISTRATION)
	if err != nil {
		return err
	}
	subscriptions, err := node.GetChannel(financego.SUBSCRIPTION)
	if err != nil {
		return err
	}
	for alias, size := range usage {
		log.Println("Usage", alias, ":", size)
		// Get Registration for Alias
		registration, err := financego.GetRegistrationSync(registrations, node.Cache, node.Network, node.Alias, node.Key, alias, nil)
		if err != nil {
			return err
		}
		if registration == nil {
			log.Println(errors.New(alias + " is not registered but is storing " + bcgo.SizeToString(size)))
			break
		}

		// Get Subscription for Alias
		subscription, err := financego.GetSubscriptionSync(subscriptions, node.Cache, node.Network, node.Alias, node.Key, alias, nil, productId, planId)
		if err != nil {
			return err
		}
		if subscription == nil {
			log.Println(errors.New(alias + " is not subscribed but is storing " + bcgo.SizeToString(size)))
			break
		} else {
			// Log Subscription Usage
			if registration.CustomerId != subscription.CustomerId {
				log.Println(errors.New("Registration Customer ID doesn't match Subscription Customer ID"))
				break
			}
			stripeUsageRecord, bcUsageRecord, err := financego.NewUsageRecord(node.Alias, alias, subscription.SubscriptionItemId, time.Now().Unix(), int64(size))
			if err != nil {
				return err
			}
			log.Println("UsageRecord", stripeUsageRecord)
			log.Println("UsageRecord", bcUsageRecord)
			// TODO Mine bcUsageRecord into UsageChannel
		}
	}
	return nil
}
