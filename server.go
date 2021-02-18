/*
 * Copyright 2019-2020 Aletheia Ware LLC
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
	"aletheiaware.com/aliasgo"
	"aletheiaware.com/aliasservergo"
	"aletheiaware.com/bcgo"
	"aletheiaware.com/bcnetgo"
	"aletheiaware.com/cryptogo"
	"aletheiaware.com/financego"
	"aletheiaware.com/netgo"
	"aletheiaware.com/spacego"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang/protobuf/proto"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Server struct {
	sync.RWMutex
	Root          string
	Cert          string
	Cache         *bcgo.FileCache
	Network       *bcgo.TCPNetwork
	Listener      bcgo.MiningListener
	keys          map[string]*rsa.PublicKey
	registrations map[string]*financego.Registration
	subscriptions map[string]*financego.Subscription
	validators    map[string]*bcgo.PeriodicValidator
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
	node, err := bcgo.NewNode(s.Root, s.Cache, s.Network)
	if err != nil {
		return nil, err
	}

	// Register Alias
	if err := aliasgo.Register(node, s.Listener); err != nil {
		return nil, err
	}

	return node, nil
}

func (s *Server) RegisterRegistrar(node *bcgo.Node, domain, country, currency, publishableKey, productId, planId string, priceGb uint64) (*spacego.Registrar, error) {
	// Create Registrar
	registrar := &spacego.Registrar{
		Merchant: &financego.Merchant{
			Alias:          node.Alias,
			Domain:         domain,
			Processor:      financego.PaymentProcessor_STRIPE,
			PublishableKey: publishableKey,
			RegisterUrl:    "/space-register",
		},
		Service: &financego.Service{
			ProductId:    productId,
			PlanId:       planId,
			Country:      country,
			Currency:     currency,
			GroupPrice:   int64(priceGb),
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

	if l, ok := os.LookupEnv(bcgo.LIVE_FLAG); ok {
		record.Meta = map[string]string{
			bcgo.LIVE_FLAG: l,
		}
	}

	// Write Record
	if err := Write(node, spacego.OpenRegistrarChannel(), record, spacego.THRESHOLD_ACCOUNTING, s.Listener); err != nil {
		return nil, err
	}

	return registrar, nil
}

func (s *Server) Start(node *bcgo.Node) error {
	company := os.Getenv("COMPANY")
	publishableKey := os.Getenv("STRIPE_PUBLISHABLE_KEY")
	productId := os.Getenv("STRIPE_STORAGE_PRODUCT_ID")
	planId := os.Getenv("STRIPE_STORAGE_PLAN_ID")

	// Open channels
	aliases := aliasgo.OpenAliasChannel()
	charges := spacego.OpenChargeChannel()
	invoices := spacego.OpenInvoiceChannel()
	registrations := spacego.OpenRegistrationChannel()
	subscriptions := spacego.OpenSubscriptionChannel()
	usageRecords := spacego.OpenUsageRecordChannel()
	registrars := spacego.OpenRegistrarChannel()

	// Attach triggers
	aliases.AddTrigger(func() {
		keys, err := aliasgo.AllPublicKeys(aliases, s.Cache, s.Network)
		if err != nil {
			log.Println(err)
			return
		}
		s.Lock()
		s.keys = keys
		s.Unlock()
	})
	registrations.AddTrigger(func() {
		rs := make(map[string]*financego.Registration)
		if err := bcgo.Read(registrations.Name, registrations.Head, nil, s.Cache, s.Network, node.Alias, node.Key, nil, func(entry *bcgo.BlockEntry, key, data []byte) error {
			// Unmarshal as Registration
			registration := &financego.Registration{}
			err := proto.Unmarshal(data, registration)
			if err == nil && (registration.MerchantAlias == node.Alias) {
				if _, ok := rs[registration.CustomerAlias]; !ok {
					rs[registration.CustomerAlias] = registration
				}
			}
			return nil
		}); err != nil {
			log.Println(err)
		}
		s.Lock()
		s.registrations = rs
		s.Unlock()
	})
	subscriptions.AddTrigger(func() {
		ss := make(map[string]*financego.Subscription)
		if err := bcgo.Read(subscriptions.Name, subscriptions.Head, nil, s.Cache, s.Network, node.Alias, node.Key, nil, func(entry *bcgo.BlockEntry, key, data []byte) error {
			// Unmarshal as Subscription
			subscription := &financego.Subscription{}
			err := proto.Unmarshal(data, subscription)
			if err == nil && (subscription.MerchantAlias == node.Alias) && (subscription.ProductId == productId) && (subscription.PlanId == planId) {
				if _, ok := ss[subscription.CustomerAlias]; !ok {
					ss[subscription.CustomerAlias] = subscription
				}
			}
			return nil
		}); err != nil {
			log.Println(err)
		}
		s.Lock()
		s.subscriptions = ss
		s.Unlock()
		for alias := range ss {
			// Check if validation channel is already open
			s.RLock()
			validator, ok := s.validators[alias]
			s.RUnlock()
			if ok {
				continue
			}
			log.Println("Creating Validator for", alias)
			// Open validation channel
			v := spacego.OpenValidationChannel(alias)
			if err := v.Refresh(s.Cache, s.Network); err != nil {
				log.Println(err)
			}
			// Add channel to node
			node.AddChannel(v)
			validator = spacego.GetValidator(node, v, s.Listener)
			s.Lock()
			s.validators[alias] = validator
			s.Unlock()

			metas := spacego.GetMetaChannelName(alias)
			validator.Channels[metas] = true
			m := node.GetOrOpenChannel(metas, func() *bcgo.Channel {
				return spacego.OpenMetaChannel(alias)
			})
			m.AddTrigger(func() {
				// Add delta, preview, tag channels for each file to validator
				if err := bcgo.Iterate(m.Name, m.Head, nil, s.Cache, s.Network, func(hash []byte, block *bcgo.Block) error {
					for _, entry := range block.Entry {
						hash := base64.RawURLEncoding.EncodeToString(entry.RecordHash)
						log.Println("Found file:", hash)
						deltas := spacego.GetDeltaChannelName(hash)
						validator.Channels[deltas] = true
						d := node.GetOrOpenChannel(deltas, func() *bcgo.Channel {
							return spacego.OpenDeltaChannel(hash)
						})
						if err := d.Refresh(s.Cache, s.Network); err != nil {
							log.Println(err)
						}
						previews := spacego.GetPreviewChannelName(hash)
						validator.Channels[previews] = true
						p := node.GetOrOpenChannel(previews, func() *bcgo.Channel {
							return spacego.OpenPreviewChannel(hash)
						})
						if err := p.Refresh(s.Cache, s.Network); err != nil {
							log.Println(err)
						}
						tags := spacego.GetTagChannelName(hash)
						validator.Channels[tags] = true
						t := node.GetOrOpenChannel(tags, func() *bcgo.Channel {
							return spacego.OpenTagChannel(hash)
						})
						if err := t.Refresh(s.Cache, s.Network); err != nil {
							log.Println(err)
						}
					}
					return nil
				}); err != nil {
					log.Println(err)
				}
			})
			if err := m.Refresh(s.Cache, s.Network); err != nil {
				log.Println(err)
			}
			// Start periodic validator
			go validator.Start()
		}
	})

	for _, c := range []*bcgo.Channel{
		aliases,
		charges,
		invoices,
		registrations,
		subscriptions,
		usageRecords,
		registrars,
	} {
		// Load channel
		if err := c.Refresh(s.Cache, s.Network); err != nil {
			log.Println(err)
		}
		// Add channel to node
		node.AddChannel(c)
	}

	// Serve Connect Requests
	go bcnetgo.BindTCP(bcgo.PORT_CONNECT, bcnetgo.ConnectPortTCPHandler(s.Network, func(address, peer string) bool {
		s.RLock()
		_, ok := s.keys[peer]
		s.RUnlock()
		if !ok {
			// Unregistered Alias
			return false
		}
		h, _, err := net.SplitHostPort(address)
		if err != nil {
			log.Println(address, err)
			return false
		}
		i := net.ParseIP(h)
		if i == nil {
			log.Println(address, "Could not parse IP:", h)
			return false
		}
		// DNS lookup peer to get IP addresses
		ips, err := net.LookupIP(peer)
		if err != nil {
			log.Println(address, err)
			return false
		}
		for _, ip := range ips {
			if ip.Equal(i) {
				return true
			}
		}
		return false
	}))
	// Serve Block Requests
	go bcnetgo.BindTCP(bcgo.PORT_GET_BLOCK, bcnetgo.BlockPortTCPHandler(s.Cache))
	// Serve Head Requests
	go bcnetgo.BindTCP(bcgo.PORT_GET_HEAD, bcnetgo.HeadPortTCPHandler(s.Cache))
	// Serve Block Updates
	go bcnetgo.BindTCP(bcgo.PORT_BROADCAST, bcnetgo.BroadcastPortTCPHandler(s.Cache, s.Network, func(name string) (*bcgo.Channel, error) {
		return node.GetOrOpenChannel(name, func() *bcgo.Channel {
			// TODO allow if all record creators are registered and prefix is one of;
			//   SPACE_PREFIX_DELTA
			//   SPACE_PREFIX_META
			//   SPACE_PREFIX_PREVIEW
			//   SPACE_PREFIX_TAG
			if strings.HasPrefix(name, spacego.SPACE_PREFIX) {
				c := bcgo.OpenPoWChannel(name, spacego.GetThreshold(name))
				if err := c.Refresh(s.Cache, s.Network); err != nil {
					log.Println(err)
				}
				return c
			}
			return nil
		}), nil
	}))

	if n := s.Network; n != nil {
		for _, p := range n.Peers() {
			if p != "" && p != "localhost" {
				if err := n.Connect(p, []byte(node.Alias)); err != nil {
					log.Println(err)
				}
			}
		}
	}

	// Redirect HTTP Requests to HTTPS
	go http.ListenAndServe(":80", http.HandlerFunc(netgo.HTTPSRedirect(node.Alias, map[string]bool{
		"/":                        true,
		"/alias":                   true,
		"/alias-register":          true,
		"/block":                   true,
		"/channel":                 true,
		"/channels":                true,
		"/keys":                    true,
		"/registrar":               true,
		"/registrars":              true,
		"/space-register":          true,
		"/space-subscribe-storage": true,
	})))

	// Serve Web Requests
	mux := http.NewServeMux()
	mux.HandleFunc("/", netgo.StaticHandler("html/static"))
	aliasTemplate, err := template.ParseFiles("html/template/alias.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/alias", aliasservergo.AliasHandler(aliases, s.Cache, aliasTemplate))
	aliasRegistrationTemplate, err := template.ParseFiles("html/template/alias-register.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/alias-register", aliasservergo.AliasRegistrationHandler(aliases, node, aliasgo.ALIAS_THRESHOLD, s.Listener, aliasRegistrationTemplate))
	blockTemplate, err := template.ParseFiles("html/template/block.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/block", bcnetgo.BlockHandler(s.Cache, blockTemplate))
	channelTemplate, err := template.ParseFiles("html/template/channel.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/channel", bcnetgo.ChannelHandler(s.Cache, channelTemplate))
	channelListTemplate, err := template.ParseFiles("html/template/channel-list.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/channels", bcnetgo.ChannelListHandler(s.Cache, channelListTemplate, node.GetChannels))
	mux.HandleFunc("/keys", cryptogo.KeyShareHandler(make(cryptogo.KeyShareStore), 2*time.Minute))
	registrarTemplate, err := template.ParseFiles("html/template/registrar.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/registrar", RegistrarHandler(registrarTemplate, func(alias string) (*spacego.Registrar, error) {
		return spacego.GetRegistrar(registrars, s.Cache, nil, alias) // Pass nil network to avoid request propagation
	}))
	registrarListTemplate, err := template.ParseFiles("html/template/registrar-list.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/registrars", RegistrarListHandler(registrarListTemplate, func() []*spacego.Registrar {
		return spacego.GetRegistrars(registrars, s.Cache, nil) // Pass nil network to avoid request propagation
	}))
	mux.HandleFunc("/stripe-webhook", bcnetgo.StripeWebhookHandler(StripeEventHandler))
	registrationTemplate, err := template.ParseFiles("html/template/space-register.go.html")
	if err != nil {
		return err
	}
	processor := &financego.Stripe{}
	mux.HandleFunc("/space-register", bcnetgo.RegistrationHandler(node.Alias, company, publishableKey, registrationTemplate, financego.Register(node, processor, aliases, registrations, spacego.THRESHOLD_ACCOUNTING, s.Listener)))
	subscriptionTemplate, err := template.ParseFiles("html/template/space-subscribe-storage.go.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/space-subscribe-storage", bcnetgo.SubscriptionHandler(subscriptionTemplate, "/subscribed-storage.html", financego.Subscribe(node, processor, aliases, subscriptions, spacego.THRESHOLD_ACCOUNTING, s.Listener, productId, planId)))

	// Periodically measure storage usage per customer
	ticker := time.NewTicker(24 * time.Hour) // Daily
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-ticker.C:
				s.MeasureStorageUsage(node, processor, usageRecords, productId, planId)
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

func (s *Server) MeasureStorageUsage(node *bcgo.Node, processor financego.Processor, usageRecords *bcgo.Channel, productId, planId string) {
	usage, err := s.Cache.MeasureStorageUsage(spacego.SPACE_PREFIX)
	if err != nil {
		log.Println(err)
		return
	}
	for alias, size := range usage {
		log.Println("Usage", alias, ":", bcgo.DecimalSizeToString(size))

		// Get rsa.PublicKey for Alias
		publicKey, ok := s.keys[alias]
		if !ok {
			log.Println(fmt.Errorf(aliasgo.ERROR_PUBLIC_KEY_NOT_FOUND, alias))
			continue
		}

		// Get Registration for Alias
		registration, ok := s.registrations[alias]
		if !ok || registration == nil {
			log.Println(errors.New(alias + " is not registered but is storing " + bcgo.DecimalSizeToString(size)))
			// TODO add alias to blacklist. don't respond to block requests containing records created by blacklisted alias. remove from blacklist when subscription is added.
			// TODO ignore peers from this blacklist
			continue
		}

		// Get Subscription for Alias
		subscription, ok := s.subscriptions[alias]
		if !ok || subscription == nil {
			log.Println(errors.New(alias + " is not subscribed but is storing " + bcgo.DecimalSizeToString(size)))
			// TODO if alias is registered but not subscribed bill the monthly rate divided by the average number of days in a month (365.25/12) or the minimum charge amount (whichever is greater)
			continue
		}
		// Log Subscription Usage
		if registration.CustomerId != subscription.CustomerId {
			log.Println(errors.New("Registration Customer ID doesn't match Subscription Customer ID"))
			continue
		}
		usageRecord, err := processor.NewUsageRecord(node.Alias, alias, subscription.SubscriptionId, subscription.SubscriptionItemId, productId, planId, time.Now().Unix(), int64(size))
		if err != nil {
			log.Println(err)
			continue
		}
		data, err := proto.Marshal(usageRecord)
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
		reference, err := bcgo.WriteRecord(usageRecords.Name, s.Cache, record)
		if err != nil {
			log.Println(err)
			continue
		}
		log.Println("Wrote Usage Record", base64.RawURLEncoding.EncodeToString(reference.RecordHash))
	}
	// Mine UsageChannel
	if _, _, err := node.Mine(usageRecords, spacego.THRESHOLD_ACCOUNTING, s.Listener); err != nil {
		log.Println(err)
		return
	}

	if err := usageRecords.Push(s.Cache, node.Network); err != nil {
		log.Println(err)
		return
	}
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
				productId := args[5]
				planId := args[6]
				priceGb, err := strconv.Atoi(args[7])
				if err != nil {
					log.Println(err)
					return
				}
				if priceGb < 0 {
					log.Println("Storage price per Gigabyte per month must be postive")
					return
				}
				node, err := bcgo.NewNode(s.Root, s.Cache, s.Network)
				if err != nil {
					log.Println(err)
					return
				}
				registrar, err := s.RegisterRegistrar(node, domain, country, currency, publishableKey, productId, planId, uint64(priceGb))
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Registered")
				log.Println(registrar)
			} else {
				log.Println("register-registrar <domain> <country-code> <currency-code> <publishable-key> <product-id> <plan-id> <price-per-gb>")
			}
		case "start":
			node, err := bcgo.NewNode(s.Root, s.Cache, s.Network)
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

	network := bcgo.NewTCPNetwork(peers...)

	server := &Server{
		Root:          rootDir,
		Cert:          certDir,
		Cache:         cache,
		Network:       network,
		Listener:      &bcgo.LoggingMiningListener{},
		keys:          make(map[string]*rsa.PublicKey),
		registrations: make(map[string]*financego.Registration),
		subscriptions: make(map[string]*financego.Subscription),
		validators:    make(map[string]*bcgo.PeriodicValidator),
	}

	server.Handle(os.Args[1:])
}

func Write(node *bcgo.Node, channel *bcgo.Channel, record *bcgo.Record, threshold uint64, listener bcgo.MiningListener) error {
	if err := channel.Refresh(node.Cache, node.Network); err != nil {
		log.Println(err)
	}

	// Write record to cache
	reference, err := bcgo.WriteRecord(channel.Name, node.Cache, record)
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
