/*
 * Copyright 2018 Aletheia Ware LLC
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
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	bc "github.com/AletheiaWareLLC/bcgo"
	bcutils "github.com/AletheiaWareLLC/bcgo/utils"
	space "github.com/AletheiaWareLLC/spacego"
	"github.com/golang/protobuf/proto"
	stripe "github.com/stripe/stripe-go"
	customer "github.com/stripe/stripe-go/customer"
	subscription "github.com/stripe/stripe-go/sub"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"path"
	"strings"
	"time"
)

var Cache string
var Node *bc.Node
var Channels map[string]*bc.Channel

func main() {
	// Load cache directory
	c, ok := os.LookupEnv("CACHE")
	if !ok {
		u, err := user.Current()
		if err != nil {
			log.Println(err)
			return
		}
		c = path.Join(u.HomeDir, "bc")
	}
	Cache = c
	// Load private key
	k, err := space.GetOrCreatePrivateKey()
	if err != nil {
		log.Println(err)
		return
	}
	Node = &bc.Node{
		Key: k,
	}
	registration := &bc.Channel{
		Name:      space.SPACE_REGISTRATION,
		Threshold: bc.THRESHOLD_STANDARD,
		Cache:     Cache,
	}
	registration.LoadHead()
	Channels = make(map[string]*bc.Channel)
	Channels[space.SPACE_REGISTRATION] = registration

	// Serve Block Requests
	go bind(bc.PORT_BLOCK, handleBlock)
	// Serve Head Requests
	go bind(bc.PORT_HEAD, handleHead)
	// Serve Status Requests
	go bind(bc.PORT_STATUS, handleStatus)
	// Serve Write Requests
	go bind(bc.PORT_WRITE, handleWrite)
	/*
		// Serve HTTPS HTML Requests
		go log.Fatal(http.ListenAndServeTLS(":443", "server.crt", "server.key", http.HandlerFunc(serve)))
		// Redirect HTTP HTML Requests to HTTPS
		log.Fatal(http.ListenAndServe(":80", http.HandlerFunc(redirect)))
	*/
	// Serve HTTP HTML Requests
	log.Fatal(http.ListenAndServe(":80", http.HandlerFunc(serve)))
}

func bind(port int, handler func(net.Conn)) {
	address := fmt.Sprintf(":%d", port)
	l, err := net.Listen("tcp", address)
	if err != nil {
		log.Println("Error listening", err)
		return
	}
	defer l.Close()
	log.Println("Listening on" + address)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println("Error accepting", err)
			return
		}
		go handler(conn)
	}
}

func redirect(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	log.Println("Redirecting to", target)
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}

func serve(w http.ResponseWriter, r *http.Request) {
	log.Println("URL Path", r.URL.Path)
	switch r.URL.Path {
	case "/register":
		switch r.Method {
		case "GET":
			t, err := template.ParseFiles("template/register.html")
			if err != nil {
				log.Println(err)
				return
			}
			data := struct {
				Description string
				Key         string
				Name        string
			}{
				Description: "Mining as a Service",
				Key:         os.Getenv("STRIPE_PUBLISHABLE_KEY"),
				Name:        "Space",
			}
			log.Println("Data", data)
			err = t.Execute(w, data)
			if err != nil {
				log.Println(err)
				return
			}
		case "POST":
			log.Println("Request", r)
			publicKeyFormat := r.PostFormValue("publicKeyFormat")
			log.Println("PublicKeyFormat", publicKeyFormat)
			publicKeyString := r.PostFormValue("publicKey")
			log.Println("PublicKey", publicKeyString)
			stripeEmail := r.PostFormValue("stripeEmail")
			log.Println("Email", stripeEmail)
			// stripeBillingName := r.PostFormValue("stripeBillingName")
			// stripeBillingAddressLine1 := r.PostFormValue("stripeBillingAddressLine1")
			// stripeBillingAddressCity := r.PostFormValue("stripeBillingAddressCity")
			// stripeBillingAddressZip := r.PostFormValue("stripeBillingAddressZip")
			// stripeBillingAddressCountry := r.PostFormValue("stripeBillingAddressCountry")
			// stripeBillingAddressCountryCode := r.PostFormValue("stripeBillingAddressCountryCode")
			// stripeBillingAddressState := r.PostFormValue("stripeBillingAddressState")
			stripeToken := r.PostFormValue("stripeToken")
			log.Println("Token", stripeToken)
			// stripeTokenType := r.PostFormValue("stripeTokenType")

			stripe.Key = os.Getenv("STRIPE_SECRET_KEY")

			// Create new Stripe customer
			customerParams := &stripe.CustomerParams{
				Description: stripe.String("Space Customer"),
				Email:       stripe.String(stripeEmail),
			}
			if err := customerParams.SetSource(stripeToken); err != nil {
				log.Println(err)
				return
			}
			cus, err := customer.New(customerParams)
			if err != nil {
				log.Println(err)
				return
			}

			productId := os.Getenv("STRIPE_PRODUCT_ID")
			planId := os.Getenv("STRIPE_PLAN_ID")

			// Create new Stripe subscription
			subscriptionParams := &stripe.SubscriptionParams{
				Customer: stripe.String(cus.ID),
				Items: []*stripe.SubscriptionItemsParams{
					{
						Plan: stripe.String(planId),
					},
				},
			}
			sub, err := subscription.New(subscriptionParams)
			if err != nil {
				log.Println(err)
				return
			}

			publicKeyBytes, err := base64.RawURLEncoding.DecodeString(publicKeyString)
			if err != nil {
				log.Println(err)
				return
			}
			publicKeyHash := bcutils.Hash(publicKeyBytes)

			// Create registration
			registration := &space.Registration{
				PublicKey:      publicKeyHash,
				CustomerId:     cus.ID,
				PaymentId:      stripeToken,
				ProductId:      productId,
				PlanId:         planId,
				SubscriptionId: sub.ID,
			}
			log.Println("Registration", registration)
			data, err := proto.Marshal(registration)
			if err != nil {
				log.Println(err)
				return
			}

			// Decode public key string to rsa.PublicKey
			pub, err := bcutils.RSAPublicKeyFromBytes(publicKeyBytes)
			if err != nil {
				log.Println(err)
				return
			}

			// Create list of recipients (user + server)
			recipients := [2]*rsa.PublicKey{pub, &Node.Key.PublicKey}
			log.Println("Recipients", recipients)

			// Create message from server to recipients
			message, err := bc.CreateMessage(Node.Key, recipients[:], nil, data)
			if err != nil {
				log.Println(err)
				return
			}

			log.Println("Message", message)

			data, err = proto.Marshal(message)
			if err != nil {
				log.Println(err)
				return
			}

			entries := [1]*bc.BlockEntry{
				&bc.BlockEntry{
					MessageHash: bcutils.Hash(data),
					Message:     message,
				},
			}

			// Mine message into blockchain
			hash, block, err := Node.Mine(Channels[space.SPACE_REGISTRATION], entries[:])
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("Hash", hash)
			log.Println("Block", block)

			http.Redirect(w, r, "/success.html", http.StatusFound)
		default:
			log.Println("Unsupported method", r.Method)
		}
	default:
		http.ServeFile(w, r, path.Join("static", r.URL.Path))
	}
}

func handleBlock(conn net.Conn) {
	defer conn.Close()
	log.Println("handleBlock:22222")
	request, err := bc.ReadReference(conn)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Reference", request)
	channel := request.ChannelName
	c, err := GetChannel(channel)
	if err != nil {
		log.Println(err)
		return
	}
	hash := request.BlockHash
	if hash != nil && len(hash) > 0 {
		// Read from cache
		block, err := bc.ReadBlockFile(c.Cache, hash)
		if err != nil {
			log.Println(err)
			return
		}
		// Write to connection
		if err := bc.WriteBlock(conn, block); err != nil {
			log.Println(err)
			return
		}
	} else {
		hash := request.MessageHash
		if hash != nil && len(hash) > 0 {
			// Search through chain until message hash is found, and return the containing block
			b := c.Head
			for b != nil {
				for _, e := range b.Entry {
					if bytes.Equal(e.MessageHash, hash) {
						log.Println("Found message, writing block")
						// Write to connection
						if err := bc.WriteBlock(conn, b); err != nil {
							log.Println(err)
						}
						return
					}
				}
				h := b.Previous
				if h != nil && len(h) > 0 {
					b, err = bc.ReadBlockFile(c.Cache, h)
					if err != nil {
						log.Println(err)
						return
					}
				} else {
					b = nil
				}
			}
		} else {
			log.Println("Missing block hash and message hash")
			return
		}
	}
}

func handleHead(conn net.Conn) {
	defer conn.Close()
	log.Println("handleHead:22232")
	request, err := bc.ReadReference(conn)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Reference", request)
	channel := request.ChannelName
	c, err := GetChannel(channel)
	if err != nil {
		log.Println(err)
		return
	}
	reference, err := bc.ReadHeadFile(c.Cache, channel)
	if err != nil {
		log.Println(err)
		return
	}
	if err := bc.WriteReference(conn, reference); err != nil {
		log.Println(err)
		return
	}
}

func handleStatus(conn net.Conn) {
	defer conn.Close()
	log.Println("handleStatus:23222")
	log.Println("Status Request Handler not yet implemented", conn)
}

func handleWrite(conn net.Conn) {
	defer conn.Close()
	log.Println("handleWrite:23232")
	request, err := space.ReadStorageRequest(conn)
	if err != nil {
		log.Println(err)
		return
	}

	// Decode public key string to rsa.PublicKey
	publicKey, err := bcutils.RSAPublicKeyFromBytes(request.PublicKey)
	if err != nil {
		log.Println(err)
		return
	}
	publicKeyHash := bcutils.Hash(request.PublicKey)
	publicKeyHashString := base64.RawURLEncoding.EncodeToString(publicKeyHash)
	log.Println("StorageRequest", proto.Size(request), publicKeyHashString, request.CustomerId, request.PaymentId)
	if len(request.CustomerId) > 0 {
		// TODO check public key matches registered customer
		// TODO bill customer
	} else {
		if len(request.PaymentId) > 0 {
			// TODO bill payment token
		} else {
			log.Println("Missing payment information")
			// TODO if the user wants to register, POST to :443/register with publicKey, and stripe info.
			// If response is success, await new head of Space Registration channel, and decrypt to get customer id.
			return
		}
	}

	response := &space.StorageResponse{}

	// Create an array to hold at most two references (file, preview)
	references := make([]*bc.Reference, 0, 2)

	fileChannel := &bc.Channel{
		Name:      space.SPACE_FILE_PREFIX + publicKeyHashString,
		Threshold: bc.THRESHOLD_STANDARD,
		Cache:     Cache,
	}
	fileChannel.LoadHead()
	Channels[fileChannel.Name] = fileChannel
	fileReference, err := Mine(fileChannel, publicKey, request.File, nil)
	if err != nil {
		log.Println(err)
		return
	}
	// Add fileReference to response
	response.File = fileReference
	// Add fileReference to list of references
	references = append(references, response.File)

	if request.Preview != nil {
		previewChannel := &bc.Channel{
			Name:      space.SPACE_PREVIEW_PREFIX + publicKeyHashString,
			Threshold: bc.THRESHOLD_STANDARD,
			Cache:     Cache,
		}
		previewChannel.LoadHead()
		Channels[previewChannel.Name] = previewChannel
		previewReference, err := Mine(previewChannel, publicKey, request.Preview, nil)
		if err != nil {
			log.Println(err)
			return
		}
		// Add previewReference to response
		response.Preview = previewReference
		// Add previewReference to list of references
		references = append(references, response.Preview)
	}

	metaChannel := &bc.Channel{
		Name:      space.SPACE_META_PREFIX + publicKeyHashString,
		Threshold: bc.THRESHOLD_STANDARD,
		Cache:     Cache,
	}
	metaChannel.LoadHead()
	Channels[metaChannel.Name] = metaChannel
	metaReference, err := Mine(metaChannel, publicKey, request.Meta, references)
	if err != nil {
		log.Println(err)
		return
	}
	response.Meta = metaReference

	// Reply with storage response
	log.Println("StorageResponse", response)
	if err := space.WriteStorageResponse(conn, response); err != nil {
		log.Println(err)
		return
	}
}

func Mine(channel *bc.Channel, publicKey *rsa.PublicKey, bundle *space.StorageRequest_Bundle, references []*bc.Reference) (*bc.Reference, error) {
	// TODO check signature

	publicKeyBytes, err := bcutils.RSAPublicKeyToBytes(publicKey)
	if err != nil {
		return nil, err
	}
	publicKeyHash := bcutils.Hash(publicKeyBytes)

	timestamp := uint64(time.Now().UnixNano())

	recipients := [1]*bc.Message_Access{
		&bc.Message_Access{
			PublicKeyHash: publicKeyHash,
			SecretKey:     bundle.Key,
		},
	}

	// Create message
	message := &bc.Message{
		Timestamp:     timestamp,
		SenderKeyHash: publicKeyHash,
		Recipient:     recipients[:],
		Payload:       bundle.Payload,
		Signature:     bundle.Signature,
		Reference:     references,
	}

	// Marshal into byte array
	data, err := proto.Marshal(message)
	if err != nil {
		return nil, err
	}

	// Get message hash
	hash := bcutils.Hash(data)

	// Create entry array containing hash and message
	entries := [1]*bc.BlockEntry{
		&bc.BlockEntry{
			MessageHash: hash,
			Message:     message,
		},
	}

	// Mine channel in goroutine
	go func() {
		_, _, err := Node.Mine(channel, entries[:])
		if err != nil {
			log.Println(err)
			return
		}
	}()

	// Return reference to message
	return &bc.Reference{
		Timestamp:   timestamp,
		ChannelName: channel.Name,
		MessageHash: hash,
	}, nil
}

func GetChannel(name string) (*bc.Channel, error) {
	if strings.HasPrefix(name, space.SPACE_PREFIX) {
		channel := Channels[name]
		if channel == nil {
			channel = &bc.Channel{
				Name:      name,
				Threshold: bc.THRESHOLD_STANDARD,
				Cache:     Cache,
			}
			channel.LoadHead()
			Channels[name] = channel
		}
		return channel, nil
	}
	return nil, errors.New("Unknown channel: " + name)
}
