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
	"crypto/rsa"
	//"encoding/base64"
	//"fmt"
	bc "github.com/AletheiaWareLLC/bcgo"
	bcutils "github.com/AletheiaWareLLC/bcgo/utils"
	space "github.com/AletheiaWareLLC/spacego"
	"github.com/golang/protobuf/proto"
	stripe "github.com/stripe/stripe-go"
	customer "github.com/stripe/stripe-go/customer"
	subscription "github.com/stripe/stripe-go/sub"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"time"
)

type HTMLHandler struct {
}

type BlockHandler struct {
}

type HeadHandler struct {
}

type WriteHandler struct {
}

var Node *bc.Node
var registrationChannel *bc.Channel

func main() {
	// Load private key
	Key, err := space.GetOrCreatePrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	Node = &bc.Node{
		Key: Key,
	}
	registrationChannel = &bc.Channel{
		Name:      "Space Registration",
		Threshold: bc.THRESHOLD_STANDARD,
	}

	// Serve Block Requests
	go func() {
		log.Fatal(http.ListenAndServe(":23032", &BlockHandler{}))
	}()
	// Serve Head Requests
	go func() {
		log.Fatal(http.ListenAndServe(":23132", &HeadHandler{}))
	}()
	// Serve Write Requests
	go func() {
		log.Fatal(http.ListenAndServe(":23232", &WriteHandler{}))
	}()
	// Serve HTML Requests
	log.Fatal(http.ListenAndServe(":8080", &HTMLHandler{}))
	// Serve HTML Requests over HTTPS
	//log.Fatal(http.ListenAndServeTLS(":443", "server.crt", "server.key", &HTMLHandler{}))
}

func (h *HTMLHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("URL Path ", r.URL.Path)
	switch r.URL.Path {
	case "/register":
		switch r.Method {
		case "GET":
			t, err := template.ParseFiles("template/register.html")
			if err != nil {
				log.Fatal(err)
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
			log.Println("Data ", data)
			err = t.Execute(w, data)
			if err != nil {
				log.Fatal(err)
			}
		case "POST":
			log.Println("Request ", r)
			publicKeyString := r.PostFormValue("publicKey")
			stripeEmail := r.PostFormValue("stripeEmail")
			// stripeBillingName := r.PostFormValue("stripeBillingName")
			// stripeBillingAddressLine1 := r.PostFormValue("stripeBillingAddressLine1")
			// stripeBillingAddressCity := r.PostFormValue("stripeBillingAddressCity")
			// stripeBillingAddressZip := r.PostFormValue("stripeBillingAddressZip")
			// stripeBillingAddressCountry := r.PostFormValue("stripeBillingAddressCountry")
			// stripeBillingAddressCountryCode := r.PostFormValue("stripeBillingAddressCountryCode")
			// stripeBillingAddressState := r.PostFormValue("stripeBillingAddressState")
			stripeToken := r.PostFormValue("stripeToken")
			// stripeTokenType := r.PostFormValue("stripeTokenType")

			stripe.Key = os.Getenv("STRIPE_SECRET_KEY")

			// Create new Stripe customer
			customerParams := &stripe.CustomerParams{
				Description: stripe.String("Space Customer"),
				Email:       stripe.String(stripeEmail),
			}
			if err := customerParams.SetSource(stripeToken); err != nil {
				log.Fatal(err)
			}
			cus, err := customer.New(customerParams)
			if err != nil {
				log.Fatal(err)
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
				log.Fatal(err)
			}

			publicKeyBytes := []byte(publicKeyString)
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
			log.Println("Registration: ", registration)
			data, err := proto.Marshal(registration)
			if err != nil {
				log.Fatal(err)
			}

			// Decode public key string to rsa.PublicKey
			pub, err := bcutils.RSAPublicKeyFromBytes(publicKeyBytes)
			if err != nil {
				log.Fatal(err)
			}

			// Create list of recipients (user + server)
			recipients := [2]*rsa.PublicKey{pub, &Node.Key.PublicKey}

			// Create message from server to recipients
			message, err := bc.CreateMessage(Node.Key, recipients[:], nil, data)
			if err != nil {
				log.Fatal(err)
			}

			log.Println("Message: ", message)

			data, err = proto.Marshal(message)
			if err != nil {
				log.Fatal(err)
			}

			entries := [1]*bc.BlockEntry{
				&bc.BlockEntry{
					MessageHash: bcutils.Hash(data),
					Message:     message,
				},
			}

			// Mine message into blockchain
			hash, block, err := Node.Mine(registrationChannel, entries[:])
			if err != nil {
				log.Fatal(err)
			}
			log.Println("Hash: ", hash)
			log.Println("Block: ", block)

			http.Redirect(w, r, "/success.html", http.StatusFound)
		default:
			log.Println("Unsupported method: ", r.Method)
		}
	default:
		http.ServeFile(w, r, path.Join("static", r.URL.Path))
	}
}

func (h *BlockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("Block Request Handler not yet implemented ", r)
}

func (h *HeadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("Head Request Handler not yet implemented ", r)
}

func (h *WriteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("ServeHTTP:23232")
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Unmarshal as StorageRequest
	request := space.StorageRequest{}
	if err = proto.Unmarshal(data, &request); err != nil {
		log.Fatal(err)
	}
	log.Println("StorageRequest: ", request)
	// TODO if storage request has customer id, bill customer
	// TODO if storage request has payment token, bill token
	// TODO if storage request has neither, payment error

	// TODO if the user wants to register, POST to :8080/register with publicKey, and stripe info.
	// If response is success, await new head of Space Registration channel, and decrypt to get customer id.

	// TODO check public key matches registered customer

	// Decode public key string to rsa.PublicKey
	publicKey, err := bcutils.RSAPublicKeyFromBytes(request.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	publicKeyHash := bcutils.Hash(request.PublicKey)
	publicKeyHashString := string(publicKeyHash)

	response := &space.StorageResponse{}

	// Create an array to hold at most two references (file, preview)
	references := make([]*bc.Reference, 0, 2)

	fileChannel := &bc.Channel{
		Name:      "Space File " + publicKeyHashString,
		Threshold: bc.THRESHOLD_STANDARD,
		Head:      nil, // TODO load from storage
	}
	fileReference, err := Mine(fileChannel, publicKey, request.File, nil)
	if err != nil {
		log.Fatal(err)
	}
	// Add fileReference to response
	response.File = fileReference
	// Add fileReference to list of references
	references = append(references, response.File)

	if request.Preview != nil {
		previewChannel := &bc.Channel{
			Name:      "Space Preview " + publicKeyHashString,
			Threshold: bc.THRESHOLD_STANDARD,
			Head:      nil, // TODO load from storage
		}
		previewReference, err := Mine(previewChannel, publicKey, request.Preview, nil)
		if err != nil {
			log.Fatal(err)
		}
		// Add previewReference to response
		response.Preview = previewReference
		// Add previewReference to list of references
		references = append(references, response.Preview)
	}

	metaChannel := &bc.Channel{
		Name:      "Space Meta " + publicKeyHashString,
		Threshold: bc.THRESHOLD_STANDARD,
		Head:      nil, // TODO load from storage
	}
	metaReference, err := Mine(metaChannel, publicKey, request.Meta, references)
	if err != nil {
		log.Fatal(err)
	}
	response.Meta = metaReference

	// Reply with storage response
	log.Println("StorageResponse: ", response)
	result, err := proto.Marshal(response)
	if err != nil {
		log.Fatal(err)
	}
	w.Write(result)
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
			log.Fatal(err)
		}
	}()

	// Return reference to message
	return &bc.Reference{
		Timestamp:   timestamp,
		ChannelName: channel.Name,
		MessageHash: hash,
	}, nil
}
