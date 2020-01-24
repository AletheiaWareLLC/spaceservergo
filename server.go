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
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/aliasservergo"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/bcnetgo"
	"github.com/AletheiaWareLLC/cryptogo"
	"github.com/AletheiaWareLLC/financego"
	"github.com/AletheiaWareLLC/netgo"
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
	// Add Space hosts to peers
	for _, host := range spacego.GetSpaceHosts() {
		if err := bcgo.AddPeer(s.Root, host); err != nil {
			return nil, err
		}
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

func (s *Server) RegisterRegistrar(node *bcgo.Node, domain, country, currency, publishableKey, storageProductId, storagePlanId string, storagePriceGb uint64) (*spacego.Registrar, error) {
	// Create Registrar
	registrar := &spacego.Registrar{
		Merchant: CreateMerchant(node.Alias, domain, publishableKey),
		Service: &financego.Service{
			ProductId:    storageProductId,
			PlanId:       storagePlanId,
			Country:      country,
			Currency:     currency,
			GroupPrice:   int64(storagePriceGb),
			GroupSize:    1000000000, // Gigabyte
			Interval:     financego.Service_MONTHLY,
			Mode:         financego.Service_METERED_LAST_USAGE, // Last usage in month, NOT last usage ever
			SubscribeUrl: "/space-subscribe-storage",
		},
	}

	// Marshal Protobuf
	data, err := proto.Marshal(registrar)
	if err != nil {
		return nil, err
	}

	// Generate Signature
	signatureAlgorithm := cryptogo.SignatureAlgorithm_SHA512WITHRSA_PSS
	signature, err := cryptogo.CreateSignature(node.Key, cryptogo.Hash(data), signatureAlgorithm)
	if err != nil {
		return nil, err
	}

	// Create record
	record := &bcgo.Record{
		Timestamp:           bcgo.Timestamp(),
		Creator:             node.Alias,
		Payload:             data,
		EncryptionAlgorithm: cryptogo.EncryptionAlgorithm_UNKNOWN_ENCRYPTION,
		Signature:           signature,
		SignatureAlgorithm:  signatureAlgorithm,
	}

	// Write Record
	if err := Write(node, spacego.OpenRegistrarChannel(), record, bcgo.THRESHOLD_G, s.Listener); err != nil {
		return nil, err
	}

	return registrar, nil
}

func (s *Server) RegisterMiner(node *bcgo.Node, domain, country, currency, publishableKey, miningProductId, miningPlanId string, miningPriceMb uint64) (*spacego.Miner, error) {
	// Create Miner
	miner := &spacego.Miner{
		Merchant: CreateMerchant(node.Alias, domain, publishableKey),
		Service: &financego.Service{
			ProductId:    miningProductId,
			PlanId:       miningPlanId,
			Country:      country,
			Currency:     currency,
			GroupPrice:   int64(miningPriceMb),
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
	signatureAlgorithm := cryptogo.SignatureAlgorithm_SHA512WITHRSA_PSS
	signature, err := cryptogo.CreateSignature(node.Key, cryptogo.Hash(data), signatureAlgorithm)
	if err != nil {
		return nil, err
	}

	// Create record
	record := &bcgo.Record{
		Timestamp:           bcgo.Timestamp(),
		Creator:             node.Alias,
		Payload:             data,
		EncryptionAlgorithm: cryptogo.EncryptionAlgorithm_UNKNOWN_ENCRYPTION,
		Signature:           signature,
		SignatureAlgorithm:  signatureAlgorithm,
	}

	// Write Record
	if err := Write(node, spacego.OpenMinerChannel(), record, bcgo.THRESHOLD_G, s.Listener); err != nil {
		return nil, err
	}

	return miner, nil
}

func (s *Server) LoadChannel(node *bcgo.Node, channel *bcgo.Channel) {
	// Load channel
	if err := channel.LoadCachedHead(s.Cache); err != nil {
		log.Println(err)
	}
	// Pull channel
	if err := channel.Pull(s.Cache, s.Network); err != nil {
		log.Println(err)
	}
	// Add channel to node
	node.AddChannel(channel)
}

func (s *Server) Start(node *bcgo.Node) error {
	// Open channels
	aliases := aliasgo.OpenAliasChannel()
	hours := spacego.OpenHourChannel()
	days := spacego.OpenDayChannel()
	years := spacego.OpenYearChannel()
	charges := spacego.OpenChargeChannel()
	invoices := spacego.OpenInvoiceChannel()
	registrations := spacego.OpenRegistrationChannel()
	subscriptions := spacego.OpenSubscriptionChannel()
	usageRecords := spacego.OpenUsageRecordChannel()
	registrars := spacego.OpenRegistrarChannel()
	miners := spacego.OpenMinerChannel()

	hourly := bcgo.GetHourlyValidator(hours)
	daily := bcgo.GetDailyValidator(days)
	yearly := bcgo.GetYearlyValidator(years)

	for _, c := range []*bcgo.Channel{
		hours,
		days,
		years,
		aliases,
		charges,
		invoices,
		registrations,
		subscriptions,
		usageRecords,
		registrars,
		miners,
	} {
		// Add periodic validators
		c.AddValidator(hourly)
		c.AddValidator(daily)
		c.AddValidator(yearly)
		// Load channel
		s.LoadChannel(node, c)
	}

	// Open all channels listed in the periodic validation chains
	channels := make(map[string]bool)
	hourly.FillChannelSet(channels, s.Cache, s.Network)
	daily.FillChannelSet(channels, s.Cache, s.Network)
	yearly.FillChannelSet(channels, s.Cache, s.Network)

	// Unmark channels already open
	for k := range node.Channels {
		channels[k] = false
	}

	// Open all channels marked in map
	for c, b := range channels {
		if b && strings.HasPrefix(c, spacego.SPACE_PREFIX) {
			s.LoadChannel(node, bcgo.OpenPoWChannel(c, spacego.GetThreshold(c)))
		}
	}

	go hourly.Start(node, bcgo.THRESHOLD_PERIOD_HOUR, s.Listener)
	defer hourly.Stop()
	go daily.Start(node, bcgo.THRESHOLD_PERIOD_DAY, s.Listener)
	defer daily.Stop()
	go yearly.Start(node, bcgo.THRESHOLD_PERIOD_YEAR, s.Listener)
	defer yearly.Stop()

	// Serve Block Requests
	go bcnetgo.Bind(bcgo.PORT_GET_BLOCK, bcnetgo.BlockPortHandler(s.Cache, s.Network))
	// Serve Head Requests
	go bcnetgo.Bind(bcgo.PORT_GET_HEAD, bcnetgo.HeadPortHandler(s.Cache, s.Network))
	// Serve Block Updates
	go bcnetgo.Bind(bcgo.PORT_BROADCAST, bcnetgo.BroadcastPortHandler(s.Cache, s.Network, func(name string) (*bcgo.Channel, error) {
		channel, err := node.GetChannel(name)
		if err != nil {
			if strings.HasPrefix(name, spacego.SPACE_PREFIX) {
				channel = bcgo.OpenPoWChannel(name, spacego.GetThreshold(name))
				s.LoadChannel(node, channel)
			} else {
				return nil, err
			}
		}
		return channel, nil
	}))

	// Redirect HTTP Requests to HTTPS
	go http.ListenAndServe(":80", http.HandlerFunc(netgo.HTTPSRedirect(node.Alias, map[string]bool{
		"/":                        true,
		"/alias":                   true,
		"/alias-register":          true,
		"/block":                   true,
		"/channel":                 true,
		"/channels":                true,
		"/keys":                    true,
		"/miner":                   true,
		"/miners":                  true,
		"/registrar":               true,
		"/registrars":              true,
		"/space-register":          true,
		"/space-subscribe-storage": true,
		"/space-subscribe-mining":  true,
	})))

	// Serve Web Requests
	mux := http.NewServeMux()
	mux.HandleFunc("/", netgo.StaticHandler("html/static"))
	aliasTemplate, err := template.ParseFiles("html/template/alias.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/alias", aliasservergo.AliasHandler(aliases, s.Cache, s.Network, aliasTemplate))
	aliasRegistrationTemplate, err := template.ParseFiles("html/template/alias-register.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/alias-register", aliasservergo.AliasRegistrationHandler(aliases, node, aliasgo.ALIAS_THRESHOLD, s.Listener, aliasRegistrationTemplate))
	blockTemplate, err := template.ParseFiles("html/template/block.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/block", bcnetgo.BlockHandler(s.Cache, s.Network, blockTemplate))
	channelTemplate, err := template.ParseFiles("html/template/channel.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/channel", bcnetgo.ChannelHandler(s.Cache, s.Network, channelTemplate))
	channelListTemplate, err := template.ParseFiles("html/template/channel-list.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/channels", bcnetgo.ChannelListHandler(s.Cache, s.Network, channelListTemplate, node.GetChannels))
	mux.HandleFunc("/keys", cryptogo.KeyShareHandler(make(cryptogo.KeyShareStore), 2*time.Minute))
	minerTemplate, err := template.ParseFiles("html/template/miner.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/miner", MinerHandler(minerTemplate, spacego.GetMiner(miners, s.Cache, s.Network)))
	minerListTemplate, err := template.ParseFiles("html/template/miner-list.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/miners", MinerListHandler(minerListTemplate, spacego.GetMiners(miners, s.Cache, s.Network)))
	registrarTemplate, err := template.ParseFiles("html/template/registrar.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/registrar", RegistrarHandler(registrarTemplate, spacego.GetRegistrar(registrars, s.Cache, s.Network)))
	registrarListTemplate, err := template.ParseFiles("html/template/registrar-list.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/registrars", RegistrarListHandler(registrarListTemplate, spacego.GetRegistrars(registrars, s.Cache, s.Network)))
	mux.HandleFunc("/stripe-webhook", bcnetgo.StripeWebhookHandler(StripeEventHandler))
	registrationTemplate, err := template.ParseFiles("html/template/space-register.go.html")
	if err != nil {
		return err
	}
	publishableKey := os.Getenv("STRIPE_PUBLISHABLE_KEY")
	mux.HandleFunc("/space-register", bcnetgo.RegistrationHandler(aliases, registrations, node, bcgo.THRESHOLD_G, s.Listener, registrationTemplate, publishableKey))
	subscriptionTemplate, err := template.ParseFiles("html/template/space-subscribe-storage.go.html")
	if err != nil {
		return err
	}
	country := os.Getenv("STRIPE_COUNTRY")
	currency := os.Getenv("STRIPE_CURRENCY")
	storageProductId := os.Getenv("STRIPE_STORAGE_PRODUCT_ID")
	storagePlanId := os.Getenv("STRIPE_STORAGE_PLAN_ID")
	mux.HandleFunc("/space-subscribe-storage", bcnetgo.SubscriptionHandler(aliases, subscriptions, node, bcgo.THRESHOLD_G, s.Listener, subscriptionTemplate, "/subscribed-storage.html", storageProductId, storagePlanId))
	subscriptionTemplate, err = template.ParseFiles("html/template/space-subscribe-mining.go.html")
	if err != nil {
		return err
	}
	miningProductId := os.Getenv("STRIPE_MINING_PRODUCT_ID")
	miningPlanId := os.Getenv("STRIPE_MINING_PLAN_ID")
	if miningProductId != "" && miningPlanId != "" {
		mux.HandleFunc("/space-subscribe-mining", bcnetgo.SubscriptionHandler(aliases, subscriptions, node, bcgo.THRESHOLD_G, s.Listener, subscriptionTemplate, "/subscribed-mining.html", miningProductId, miningPlanId))
		mux.HandleFunc("/mining/file", MiningHandler(aliases, charges, usageRecords, node, s.Listener, country, currency, miningProductId, miningPlanId, func(record *bcgo.Record) []string {
			// Space-File-<creator-alias>
			return []string{
				spacego.SPACE_PREFIX_FILE + record.Creator,
			}
		}))
		mux.HandleFunc("/mining/meta", MiningHandler(aliases, charges, usageRecords, node, s.Listener, country, currency, miningProductId, miningPlanId, func(record *bcgo.Record) []string {
			// Space-Meta-<creator-alias>
			return []string{
				spacego.SPACE_PREFIX_META + record.Creator,
			}
		}))
		mux.HandleFunc("/mining/share", MiningHandler(aliases, charges, usageRecords, node, s.Listener, country, currency, miningProductId, miningPlanId, func(record *bcgo.Record) []string {
			// Space-Share-<receiver-alias>
			channels := make([]string, len(record.Access))
			if len(record.Access) == 0 {
				// TODO share publicly
				// channels := []string{ spacego.SPACE_SHARE_PUBLIC }
			} else {
				for i, a := range record.Access {
					channels[i] = spacego.SPACE_PREFIX_SHARE + a.Alias
				}
			}
			return channels
		}))
		mux.HandleFunc("/mining/preview", MiningHandler(aliases, charges, usageRecords, node, s.Listener, country, currency, miningProductId, miningPlanId, func(record *bcgo.Record) []string {
			// Space-Preview-<meta-record-hash>
			channels := make([]string, len(record.Reference))
			for i, r := range record.Reference {
				channels[i] = spacego.SPACE_PREFIX_PREVIEW + base64.RawURLEncoding.EncodeToString(r.RecordHash)
			}
			return channels
		}))
		mux.HandleFunc("/mining/tag", MiningHandler(aliases, charges, usageRecords, node, s.Listener, country, currency, miningProductId, miningPlanId, func(record *bcgo.Record) []string {
			// Space-Tag-<meta-record-hash>
			channels := make([]string, len(record.Reference))
			for i, r := range record.Reference {
				channels[i] = spacego.SPACE_PREFIX_TAG + base64.RawURLEncoding.EncodeToString(r.RecordHash)
			}
			return channels
		}))
	}
	// Periodically measure storage usage per customer
	ticker := time.NewTicker(24 * time.Hour) // Daily
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-ticker.C:
				MeasureStorageUsage(aliases, registrations, subscriptions, usageRecords, node, s.Cache, storageProductId, storagePlanId, s.Listener)
			case <-stop:
				ticker.Stop()
				return
			}
		}
	}()
	// Serve HTTPS Requests
	config := &tls.Config{MinVersion: tls.VersionTLS10}
	server := &http.Server{Addr: ":443", Handler: mux, TLSConfig: config}
	return server.ListenAndServeTLS(path.Join(s.Cert, "fullchain.pem"), path.Join(s.Cert, "privkey.pem"))
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
			publicKeyBytes, err := cryptogo.RSAPublicKeyToPKIXBytes(&node.Key.PublicKey)
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
					log.Println("Storage price per Gigabyte per month must be postive")
					return
				}
				node, err := bcgo.GetNode(s.Root, s.Cache, s.Network)
				if err != nil {
					log.Println(err)
					return
				}
				registrar, err := s.RegisterRegistrar(node, domain, country, currency, publishableKey, storageProductId, storagePlanId, uint64(storagePriceGb))
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
				miner, err := s.RegisterMiner(node, domain, country, currency, publishableKey, miningProductId, miningPlanId, uint64(miningPriceMb))
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
		Listener: &bcgo.PrintingMiningListener{Output: os.Stdout},
	}

	server.Handle(os.Args[1:])
}

func MiningHandler(aliases *bcgo.Channel, charges *bcgo.Channel, usageRecords *bcgo.Channel, node *bcgo.Node, listener bcgo.MiningListener, country, currency, productId, planId string, getChannelNames func(*bcgo.Record) []string) func(http.ResponseWriter, *http.Request) {
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

			if err := aliases.Pull(node.Cache, node.Network); err != nil {
				log.Println(err)
			}

			// Get rsa.PublicKey for Alias
			publicKey, err := aliasgo.GetPublicKey(aliases, node.Cache, node.Network, record.Creator)
			if err != nil {
				log.Println(err)
				return
			}

			// Verify Signature
			if err := cryptogo.VerifySignature(publicKey, cryptogo.Hash(record.Payload), record.Signature, record.SignatureAlgorithm); err != nil {
				log.Println("Signature Verification Failed", err)
				return
			}

			// Get Registration for Alias
			registrations, err := node.GetChannel(spacego.SPACE_REGISTRATION)
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
			subscriptions, err := node.GetChannel(spacego.SPACE_SUBSCRIPTION)
			if err != nil {
				log.Println(err)
				return
			}
			subscription, err := financego.GetSubscriptionSync(subscriptions, node.Cache, node.Network, node.Alias, node.Key, record.Creator, nil, productId, planId)
			if err != nil {
				log.Println(err)
				return
			}

			references := make([]*bcgo.Reference, 0)
			amount := 0

			for _, name := range names {
				threshold := spacego.GetThreshold(name)
				channel, err := node.GetChannel(name)
				if err != nil {
					if strings.HasPrefix(name, spacego.SPACE_PREFIX) {
						channel = bcgo.OpenPoWChannel(name, threshold)
						// TODO s.LoadChannel(node, channel)
						if err := channel.LoadCachedHead(node.Cache); err != nil {
							log.Println(err)
						}
						if err := channel.Pull(node.Cache, node.Network); err != nil {
							log.Println(err)
						}
						node.AddChannel(channel)
					} else {
						log.Println(err)
						return
					}
				}

				amount += size
				// Write record to cache
				reference, err := bcgo.WriteRecord(name, node.Cache, record)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Wrote Record", base64.RawURLEncoding.EncodeToString(reference.RecordHash))
				references = append(references, reference)

				writer := bufio.NewWriter(w)

				// Reply with reference
				if err := bcgo.WriteDelimitedProtobuf(writer, reference); err != nil {
					log.Println(err)
					return
				}

				// Mine channel
				_, block, err := node.Mine(channel, threshold, listener)
				if err != nil {
					log.Println(err)
					return
				}

				// Reply with block
				if err := bcgo.WriteDelimitedProtobuf(writer, block); err != nil {
					log.Println(err)
					return
				}

				if err := channel.Push(node.Cache, node.Network); err != nil {
					log.Println(err)
				}
			}

			access := map[string]*rsa.PublicKey{
				record.Creator: publicKey,
				node.Alias:     &node.Key.PublicKey,
			}

			if subscription == nil {
				// Divide bytes by 200000 = $0.05 per Mb
				cost := int64(math.Ceil(float64(amount) / 200000.0))
				// Charge Customer
				stripeCharge, bcCharge, err := financego.NewCustomerCharge(registration, productId, planId, country, currency, cost, fmt.Sprintf("Space Remote Mining Charge %dbytes", amount))
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Charge", stripeCharge)
				log.Println("Charge", bcCharge)
				data, err := proto.Marshal(bcCharge)
				if err != nil {
					log.Println(err)
					return
				}
				_, record, err := bcgo.CreateRecord(bcgo.Timestamp(), node.Alias, node.Key, access, references, data)
				if err != nil {
					log.Println(err)
					return
				}
				if err := Write(node, charges, record, bcgo.THRESHOLD_G, listener); err != nil {
					log.Println(err)
					return
				}
			} else {
				// Log Subscription Usage
				if registration.CustomerId != subscription.CustomerId {
					log.Println("Registration Customer ID doesn't match Subscription Customer ID")
					return
				}
				stripeUsageRecord, bcUsageRecord, err := financego.NewUsageRecord(node.Alias, record.Creator, subscription.SubscriptionId, subscription.SubscriptionItemId, productId, planId, time.Now().Unix(), int64(amount))
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("UsageRecord", stripeUsageRecord)
				log.Println("UsageRecord", bcUsageRecord)
				data, err := proto.Marshal(bcUsageRecord)
				if err != nil {
					log.Println(err)
					return
				}
				_, record, err := bcgo.CreateRecord(bcgo.Timestamp(), node.Alias, node.Key, access, references, data)
				if err != nil {
					log.Println(err)
					return
				}
				if err := Write(node, usageRecords, record, bcgo.THRESHOLD_G, listener); err != nil {
					log.Println(err)
					return
				}
			}
		default:
			log.Println("Unsupported method", r.Method)
		}
	}
}

func MeasureStorageUsage(aliases *bcgo.Channel, registrations *bcgo.Channel, subscriptions *bcgo.Channel, usageRecords *bcgo.Channel, node *bcgo.Node, cache *bcgo.FileCache, productId, planId string, listener bcgo.MiningListener) {
	usage, err := cache.MeasureStorageUsage(spacego.SPACE_PREFIX)
	if err != nil {
		log.Println(err)
		return
	}
	for alias, size := range usage {
		log.Println("Usage", alias, ":", bcgo.DecimalSizeToString(size))

		// Get rsa.PublicKey for Alias
		publicKey, err := aliasgo.GetPublicKey(aliases, cache, node.Network, alias)
		if err != nil {
			log.Println(err)
			continue
		}

		// Get Registration for Alias
		registration, err := financego.GetRegistrationSync(registrations, cache, node.Network, node.Alias, node.Key, alias, nil)
		if err != nil {
			log.Println(err)
			continue
		}
		if registration == nil {
			log.Println(errors.New(alias + " is not registered but is storing " + bcgo.DecimalSizeToString(size)))
			continue
		}

		// Get Subscription for Alias
		subscription, err := financego.GetSubscriptionSync(subscriptions, cache, node.Network, node.Alias, node.Key, alias, nil, productId, planId)
		if err != nil {
			log.Println(err)
			continue
		}
		if subscription == nil {
			log.Println(errors.New(alias + " is not subscribed but is storing " + bcgo.DecimalSizeToString(size)))
			// TODO if alias is registered but not subscribed bill the monthly rate divided by the average number of days in a month (365.25/12) or the minimum charge amount (whichever is greater)
			continue
		} else {
			// Log Subscription Usage
			if registration.CustomerId != subscription.CustomerId {
				log.Println(errors.New("Registration Customer ID doesn't match Subscription Customer ID"))
				continue
			}
			stripeUsageRecord, bcUsageRecord, err := financego.NewUsageRecord(node.Alias, alias, subscription.SubscriptionId, subscription.SubscriptionItemId, productId, planId, time.Now().Unix(), int64(size))
			if err != nil {
				log.Println(err)
				continue
			}
			log.Println("UsageRecord", stripeUsageRecord)
			log.Println("UsageRecord", bcUsageRecord)
			data, err := proto.Marshal(bcUsageRecord)
			if err != nil {
				log.Println(err)
				continue
			}
			access := map[string]*rsa.PublicKey{
				alias:      publicKey,
				node.Alias: &node.Key.PublicKey,
			}
			_, record, err := bcgo.CreateRecord(bcgo.Timestamp(), node.Alias, node.Key, access, nil, data)
			if err != nil {
				log.Println(err)
				continue
			}
			// Write record to cache
			reference, err := bcgo.WriteRecord(usageRecords.GetName(), cache, record)
			if err != nil {
				log.Println(err)
				continue
			}
			log.Println("Wrote Usage Record", base64.RawURLEncoding.EncodeToString(reference.RecordHash))
		}
	}
	// Mine UsageChannel
	if _, _, err := node.Mine(usageRecords, bcgo.THRESHOLD_G, listener); err != nil {
		log.Println(err)
		return
	}

	if err := usageRecords.Push(cache, node.Network); err != nil {
		log.Println(err)
		return
	}
}

func Write(node *bcgo.Node, channel *bcgo.Channel, record *bcgo.Record, threshold uint64, listener bcgo.MiningListener) error {
	// Update Channel
	if err := channel.LoadCachedHead(node.Cache); err != nil {
		log.Println(err)
	}
	if err := channel.Pull(node.Cache, node.Network); err != nil {
		log.Println(err)
	}

	// Write record to cache
	reference, err := bcgo.WriteRecord(channel.GetName(), node.Cache, record)
	if err != nil {
		return err
	}
	log.Println("Wrote Record", base64.RawURLEncoding.EncodeToString(reference.RecordHash))

	// Mine record into blockchain
	hash, _, err := node.Mine(channel, threshold, listener)
	if err != nil {
		return err
	}
	log.Println("Mined", base64.RawURLEncoding.EncodeToString(hash))

	// Push update to peers
	if err := channel.Push(node.Cache, node.Network); err != nil {
		log.Println(err)
	}
	return nil
}
