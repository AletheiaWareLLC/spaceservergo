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
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type Server struct {
	Root     string
	Cert     string
	Cache    *bcgo.FileCache
	Network  bcgo.Network
	Listener bcgo.MiningListener
}

func (s *Server) Init() (*bcgo.Node, error) {
	// Add Space host to peers
	if err := bcgo.AddPeer(s.Root, spacego.GetSpaceHost()); err != nil {
		return nil, err
	}

	// Add BC host to peers
	if err := bcgo.AddPeer(s.Root, bcgo.GetBCHost()); err != nil {
		return nil, err
	}

	// Create Node
	node, err := bcgo.GetNode(s.Root, s.Cache, s.Network)
	if err != nil {
		return nil, err
	}

	// Register Alias
	if err := aliasgo.Register(node, s.Listener); err != nil {
		return nil, err
	}

	return node, nil
}

func CreateMerchant(alias, domain, publishableKey string) *financego.Merchant {
	return &financego.Merchant{
		Alias:          alias,
		Domain:         domain,
		Processor:      financego.PaymentProcessor_STRIPE,
		PublishableKey: publishableKey,
		RegisterUrl:    "/space-register",
	}
}

func (s *Server) RegisterRegistrar(node *bcgo.Node, domain, country, currency, publishableKey, storageProductId, storagePlanId string, storagePriceGb int64) (*spacego.Registrar, error) {
	// Create Registrar
	registrar := &spacego.Registrar{
		Merchant: CreateMerchant(node.Alias, domain, publishableKey),
		Service: &financego.Service{
			ProductId:    storageProductId,
			PlanId:       storagePlanId,
			Country:      country,
			Currency:     currency,
			GroupPrice:   storagePriceGb,
			GroupSize:    1000000000, // Gigabyte
			Interval:     financego.Service_MONTHLY,
			Mode:         financego.Service_METERED_LAST_USAGE,
			SubscribeUrl: "/space-subscribe-storage",
		},
	}

	// Marshal Protobuf
	data, err := proto.Marshal(registrar)
	if err != nil {
		return nil, err
	}

	// Generate Signature
	signatureAlgorithm := bcgo.SignatureAlgorithm_SHA512WITHRSA_PSS
	signature, err := bcgo.CreateSignature(node.Key, bcgo.Hash(data), signatureAlgorithm)
	if err != nil {
		return nil, err
	}

	// Create record
	record := &bcgo.Record{
		Timestamp:           uint64(time.Now().UnixNano()),
		Creator:             node.Alias,
		Payload:             data,
		EncryptionAlgorithm: bcgo.EncryptionAlgorithm_UNKNOWN_ENCRYPTION,
		Signature:           signature,
		SignatureAlgorithm:  signatureAlgorithm,
	}

	// Write Record
	if err := Write(node, spacego.OpenRegistrarChannel(), record, s.Listener); err != nil {
		return nil, err
	}

	return registrar, nil
}

func (s *Server) RegisterMiner(node *bcgo.Node, domain, country, currency, publishableKey, miningProductId, miningPlanId string, miningPriceMb int64) (*spacego.Miner, error) {
	// Create Miner
	miner := &spacego.Miner{
		Merchant: CreateMerchant(node.Alias, domain, publishableKey),
		Service: &financego.Service{
			ProductId:    miningProductId,
			PlanId:       miningPlanId,
			Country:      country,
			Currency:     currency,
			GroupPrice:   miningPriceMb,
			GroupSize:    1000000, // Megabyte
			Interval:     financego.Service_MONTHLY,
			Mode:         financego.Service_METERED_SUM_USAGE,
			SubscribeUrl: "/space-subscribe-mining",
		},
	}

	// Marshal Protobuf
	data, err := proto.Marshal(miner)
	if err != nil {
		return nil, err
	}

	// Generate Signature
	signatureAlgorithm := bcgo.SignatureAlgorithm_SHA512WITHRSA_PSS
	signature, err := bcgo.CreateSignature(node.Key, bcgo.Hash(data), signatureAlgorithm)
	if err != nil {
		return nil, err
	}

	// Create record
	record := &bcgo.Record{
		Timestamp:           uint64(time.Now().UnixNano()),
		Creator:             node.Alias,
		Payload:             data,
		EncryptionAlgorithm: bcgo.EncryptionAlgorithm_UNKNOWN_ENCRYPTION,
		Signature:           signature,
		SignatureAlgorithm:  signatureAlgorithm,
	}

	// Write Record
	if err := Write(node, spacego.OpenMinerChannel(), record, s.Listener); err != nil {
		return nil, err
	}

	return miner, nil
}

func (s *Server) Start(node *bcgo.Node) error {
	// Open channels
	aliases := aliasgo.OpenAliasChannel()
	if err := bcgo.LoadHead(aliases, s.Cache, s.Network); err != nil {
		log.Println(err)
	} else if err := bcgo.Pull(aliases, s.Cache, s.Network); err != nil {
		log.Println(err)
	}
	node.AddChannel(aliases)

	charges := financego.OpenChargeChannel()
	if err := bcgo.LoadHead(charges, s.Cache, s.Network); err != nil {
		log.Println(err)
	} else if err := bcgo.Pull(charges, s.Cache, s.Network); err != nil {
		log.Println(err)
	}
	node.AddChannel(charges)

	registrations := financego.OpenRegistrationChannel()
	if err := bcgo.LoadHead(registrations, s.Cache, s.Network); err != nil {
		log.Println(err)
	} else if err := bcgo.Pull(registrations, s.Cache, s.Network); err != nil {
		log.Println(err)
	}
	node.AddChannel(registrations)

	subscriptions := financego.OpenSubscriptionChannel()
	if err := bcgo.LoadHead(subscriptions, s.Cache, s.Network); err != nil {
		log.Println(err)
	} else if err := bcgo.Pull(subscriptions, s.Cache, s.Network); err != nil {
		log.Println(err)
	}
	node.AddChannel(subscriptions)

	usageRecords := financego.OpenUsageRecordChannel()
	if err := bcgo.LoadHead(usageRecords, s.Cache, s.Network); err != nil {
		log.Println(err)
	} else if err := bcgo.Pull(usageRecords, s.Cache, s.Network); err != nil {
		log.Println(err)
	}
	node.AddChannel(usageRecords)

	node.AddChannel(spacego.OpenRegistrarChannel())
	node.AddChannel(spacego.OpenMinerChannel())

	// Serve Block Requests
	go bcnetgo.Bind(bcgo.PORT_GET_BLOCK, bcnetgo.BlockPortHandler(s.Cache, s.Network))
	// Serve Head Requests
	go bcnetgo.Bind(bcgo.PORT_GET_HEAD, bcnetgo.HeadPortHandler(s.Cache, s.Network))
	// Serve Block Updates
	go bcnetgo.Bind(bcgo.PORT_BROADCAST, bcnetgo.BroadcastPortHandler(s.Cache, s.Network, func(name string) (bcgo.Channel, error) {
		channel, err := node.GetChannel(name)
		if err != nil {
			if strings.HasPrefix(name, spacego.SPACE_PREFIX) {
				channel = bcgo.OpenPoWChannel(name, bcgo.THRESHOLD_STANDARD)
				if err := bcgo.LoadHead(channel, s.Cache, s.Network); err != nil {
					log.Println(err)
				}
				if err := bcgo.Pull(channel, s.Cache, s.Network); err != nil {
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
	go http.ListenAndServe(":80", http.HandlerFunc(bcnetgo.HTTPSRedirect(map[string]bool{
		"/":                        true,
		"/alias":                   true,
		"/alias-register":          true,
		"/block":                   true,
		"/channel":                 true,
		"/channels":                true,
		"/keys":                    true,
		"/space-register":          true,
		"/space-subscribe-storage": true,
		"/space-subscribe-mining":  true,
	})))

	// Serve Web Requests
	mux := http.NewServeMux()
	mux.HandleFunc("/", bcnetgo.StaticHandler)
	aliasTemplate, err := template.ParseFiles("html/template/alias.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/alias", aliasservergo.AliasHandler(aliases, s.Cache, s.Network, aliasTemplate))
	aliasRegistrationTemplate, err := template.ParseFiles("html/template/alias-register.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/alias-register", aliasservergo.AliasRegistrationHandler(aliases, node, s.Listener, aliasRegistrationTemplate))
	blockTemplate, err := template.ParseFiles("html/template/block.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/block", bcnetgo.BlockHandler(s.Cache, s.Network, blockTemplate))
	channelTemplate, err := template.ParseFiles("html/template/channel.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/channel", bcnetgo.ChannelHandler(s.Cache, s.Network, channelTemplate))
	channelListTemplate, err := template.ParseFiles("html/template/channel-list.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/channels", bcnetgo.ChannelListHandler(s.Cache, s.Network, channelListTemplate, node.GetChannels))
	mux.HandleFunc("/keys", bcnetgo.KeyShareHandler(make(bcnetgo.KeyShareStore), 2*time.Minute))
	mux.HandleFunc("/stripe-webhook", bcnetgo.StripeWebhookHandler)
	registrationTemplate, err := template.ParseFiles("html/template/space-register.html")
	if err != nil {
		return err
	}
	publishableKey := os.Getenv("STRIPE_PUBLISHABLE_KEY")
	mux.HandleFunc("/space-register", bcnetgo.RegistrationHandler(aliases, node, s.Listener, registrationTemplate, publishableKey))
	subscriptionTemplate, err := template.ParseFiles("html/template/space-subscribe-storage.html")
	if err != nil {
		return err
	}
	storageProductId := os.Getenv("STRIPE_STORAGE_PRODUCT_ID")
	storagePlanId := os.Getenv("STRIPE_STORAGE_PLAN_ID")
	mux.HandleFunc("/space-subscribe-storage", bcnetgo.SubscriptionHandler(aliases, node, s.Listener, subscriptionTemplate, "/subscribed-storage.html", storageProductId, storagePlanId))
	subscriptionTemplate, err = template.ParseFiles("html/template/space-subscribe-mining.html")
	if err != nil {
		return err
	}
	miningProductId := os.Getenv("STRIPE_MINING_PRODUCT_ID")
	miningPlanId := os.Getenv("STRIPE_MINING_PLAN_ID")
	if miningProductId != "" && miningPlanId != "" {
		mux.HandleFunc("/space-subscribe-mining", bcnetgo.SubscriptionHandler(aliases, node, s.Listener, subscriptionTemplate, "/subscribed-mining.html", miningProductId, miningPlanId))
		mux.HandleFunc("/mining/file", MiningHandler(aliases, node, s.Listener, miningProductId, miningPlanId, func(record *bcgo.Record) []string {
			// Space-File-<creator-alias>
			return []string{
				spacego.SPACE_PREFIX_FILE + record.Creator,
			}
		}))
		mux.HandleFunc("/mining/meta", MiningHandler(aliases, node, s.Listener, miningProductId, miningPlanId, func(record *bcgo.Record) []string {
			// Space-Meta-<creator-alias>
			return []string{
				spacego.SPACE_PREFIX_META + record.Creator,
			}
		}))
		mux.HandleFunc("/mining/share", MiningHandler(aliases, node, s.Listener, miningProductId, miningPlanId, func(record *bcgo.Record) []string {
			// Space-Share-<receiver-alias>
			channels := make([]string, len(record.Access))
			if len(record.Access) == 0 {
				// TODO share publicly
			} else {
				for i, a := range record.Access {
					channels[i] = spacego.SPACE_PREFIX_SHARE + a.Alias
				}
			}
			return channels
		}))
		mux.HandleFunc("/mining/preview", MiningHandler(aliases, node, s.Listener, miningProductId, miningPlanId, func(record *bcgo.Record) []string {
			// Space-Preview-<meta-record-hash>
			// TODO handle all References
			return []string{
				spacego.SPACE_PREFIX_PREVIEW + base64.RawURLEncoding.EncodeToString(record.Reference[0].RecordHash),
			}
		}))
		mux.HandleFunc("/mining/tag", MiningHandler(aliases, node, s.Listener, miningProductId, miningPlanId, func(record *bcgo.Record) []string {
			// Space-Tag-<meta-record-hash>
			// TODO handle all References
			return []string{
				spacego.SPACE_PREFIX_TAG + base64.RawURLEncoding.EncodeToString(record.Reference[0].RecordHash),
			}
		}))
	}
	// Periodically measure storage usage per customer
	ticker := time.NewTicker(24 * time.Hour) // Daily
	quiter := make(chan struct{})
	defer close(quiter)
	go func() {
		for {
			select {
			case <-ticker.C:
				if err := MeasureStorageUsage(node, s.Cache, storageProductId, storagePlanId); err != nil {
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
	return http.ListenAndServeTLS(":443", path.Join(s.Cert, "fullchain.pem"), path.Join(s.Cert, "privkey.pem"), mux)
}

func (s *Server) Handle(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "init":
			PrintLegalese(os.Stdout)
			node, err := s.Init()
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("Initialized")
			log.Println(node.Alias)
			publicKeyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(&node.Key.PublicKey)
			if err != nil {
				log.Println(err)
				return
			}
			log.Println(base64.RawURLEncoding.EncodeToString(publicKeyBytes))
		case "register-registrar":
			if len(args) > 7 {
				domain := args[1]
				country := args[2]
				currency := args[3]
				publishableKey := args[4]
				storageProductId := args[5]
				storagePlanId := args[6]
				storagePriceGb, err := strconv.Atoi(args[7])
				if err != nil {
					log.Println(err)
					return
				}
				if storagePriceGb < 0 {
					log.Println("Storage price per Gigabyte must be postive")
					return
				}
				node, err := bcgo.GetNode(s.Root, s.Cache, s.Network)
				if err != nil {
					log.Println(err)
					return
				}
				registrar, err := s.RegisterRegistrar(node, domain, country, currency, publishableKey, storageProductId, storagePlanId, int64(storagePriceGb))
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Registered Registrar")
				log.Println(registrar)
			} else {
				log.Println("register-registrar <domain> <country-code> <currency-code> <publishable-key> <storage-product-id> <storage-plan-id> <storage-price-per-gb>")
			}
		case "register-miner":
			if len(args) > 7 {
				domain := args[1]
				country := args[2]
				currency := args[3]
				publishableKey := args[4]
				miningProductId := args[5]
				miningPlanId := args[6]
				miningPriceMb, err := strconv.Atoi(args[7])
				if err != nil {
					log.Println(err)
					return
				}
				if miningPriceMb < 0 {
					log.Println("Mining price per Megabyte must be postive")
					return
				}
				node, err := bcgo.GetNode(s.Root, s.Cache, s.Network)
				if err != nil {
					log.Println(err)
					return
				}
				miner, err := s.RegisterMiner(node, domain, country, currency, publishableKey, miningProductId, miningPlanId, int64(miningPriceMb))
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Registered Miner")
				log.Println(miner)
			} else {
				log.Println("register-miner <domain> <country-code> <currency-code> <publishable-key> <mining-product-id> <mining-plan-id> <mining-price-per-mb>")
			}
		case "start":
			node, err := bcgo.GetNode(s.Root, s.Cache, s.Network)
			if err != nil {
				log.Println(err)
				return
			}
			if err := s.Start(node); err != nil {
				log.Println(err)
				return
			}
		default:
			log.Println("Cannot handle", args[0])
		}
	} else {
		PrintUsage(os.Stdout)
	}
}

func PrintUsage(output io.Writer) {
	fmt.Fprintln(output, "SPACE Server Usage:")
	fmt.Fprintln(output, "\tspaceserver - display usage")
	fmt.Fprintln(output, "\tspaceserver init - initializes environment, generates key pair, and registers alias")
	fmt.Fprintln(output, "\tspaceserver register-registrar - registers node as a registrar")
	fmt.Fprintln(output, "\tspaceserver register-miner - registers node as a miner")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "\tspaceserver start - starts the server")
}

func PrintLegalese(output io.Writer) {
	fmt.Fprintln(output, "SPACE Legalese:")
	fmt.Fprintln(output, "SPACE is made available by Aletheia Ware LLC [https://aletheiaware.com] under the Terms of Service [https://aletheiaware.com/terms-of-service.html] and Privacy Policy [https://aletheiaware.com/privacy-policy.html].")
	fmt.Fprintln(output, "By continuing to use this software you agree to the Terms of Service, and Privacy Policy.")
}

func main() {
	rootDir, err := bcgo.GetRootDirectory()
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Root Directory:", rootDir)

	logFile, err := bcgo.SetupLogging(rootDir)
	if err != nil {
		log.Println(err)
		return
	}
	defer logFile.Close()
	log.Println("Log File:", logFile.Name())

	certDir, err := bcgo.GetCertificateDirectory(rootDir)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Certificate Directory:", certDir)

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

	server := &Server{
		Root:     rootDir,
		Cert:     certDir,
		Cache:    cache,
		Network:  network,
		Listener: &bcgo.PrintingMiningListener{os.Stdout},
	}

	server.Handle(os.Args[1:])
}

func MiningHandler(aliases *aliasgo.AliasChannel, node *bcgo.Node, listener bcgo.MiningListener, productId, planId string, getChannelNames func(*bcgo.Record) []string) func(http.ResponseWriter, *http.Request) {
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
			names := getChannelNames(record)
			log.Println("Channels", names)
			if len(names) == 0 {
				log.Println("Could not get channel name from record")
				return
			}

			// Calculate amount of mining record on each channel
			amount := len(names) * size

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
				// Divide bytes by 200000 = $0.05 per Mb
				cost := int64(math.Ceil(float64(amount) / 200000.0))
				// Charge Customer
				stripeCharge, bcCharge, err := financego.NewCustomerCharge(registration, cost, fmt.Sprintf("Space Remote Mining Charge %dbytes", amount))
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
				stripeUsageRecord, bcUsageRecord, err := financego.NewUsageRecord(node.Alias, record.Creator, subscription.SubscriptionItemId, time.Now().Unix(), int64(amount))
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("UsageRecord", stripeUsageRecord)
				log.Println("UsageRecord", bcUsageRecord)
				// TODO Mine bcUsageRecord into UsageChannel
			}

			for _, name := range names {
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

				// Write record to cache
				reference, err := bcgo.WriteRecord(name, node.Cache, record)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Wrote Record", base64.RawURLEncoding.EncodeToString(reference.RecordHash))

				writer := bufio.NewWriter(w)

				// Reply with reference
				if err := bcgo.WriteDelimitedProtobuf(writer, reference); err != nil {
					log.Println(err)
					return
				}

				// Mine channel
				_, block, err := node.Mine(channel, listener)
				if err != nil {
					log.Println(err)
					return
				}

				// Reply with block
				if err := bcgo.WriteDelimitedProtobuf(writer, block); err != nil {
					log.Println(err)
					return
				}

				if err := bcgo.Push(channel, node.Cache, node.Network); err != nil {
					log.Println(err)
				}
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

func Write(node *bcgo.Node, channel bcgo.ThresholdChannel, record *bcgo.Record, listener bcgo.MiningListener) error {
	// Update Channel
	if err := bcgo.LoadHead(channel, node.Cache, node.Network); err != nil {
		log.Println(err)
	} else if err := bcgo.Pull(channel, node.Cache, node.Network); err != nil {
		log.Println(err)
	}

	// Write record to cache
	reference, err := bcgo.WriteRecord(channel.GetName(), node.Cache, record)
	if err != nil {
		return err
	}
	log.Println("Wrote Record", base64.RawURLEncoding.EncodeToString(reference.RecordHash))

	// Mine record into blockchain
	hash, _, err := node.Mine(channel, listener)
	if err != nil {
		return err
	}
	log.Println("Mined", base64.RawURLEncoding.EncodeToString(hash))

	// Push update to peers
	if err := bcgo.Push(channel, node.Cache, node.Network); err != nil {
		log.Println(err)
	}
	return nil
}
