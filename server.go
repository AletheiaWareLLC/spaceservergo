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
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	// Serve Block Requests
	go bcnetgo.Bind(bcgo.PORT_BLOCK, bcnetgo.HandleBlock)
	// Serve Head Requests
	go bcnetgo.Bind(bcgo.PORT_HEAD, bcnetgo.HandleHead)
	// Serve Upload Requests
	go bcnetgo.Bind(spacego.PORT_UPLOAD, HandleUpload)

	// Serve Web Requests
	http.HandleFunc("/", bcnetgo.HandleStatic)
	http.HandleFunc("/alias", HandleAlias)
	ks := &bcnetgo.KeyStore{
		Keys: make(map[string]*bcgo.KeyShare),
	}
	http.HandleFunc("/keys", ks.HandleKeys)
	http.HandleFunc("/status", bcnetgo.HandleStatus)
	http.HandleFunc("/stripe-webhook", HandleStripeWebhook)
	http.HandleFunc("/subscription", HandleSubscribe)
	// Serve HTTPS HTML Requests
	go log.Fatal(http.ListenAndServeTLS(":443", "server.crt", "server.key", nil))
	// Redirect HTTP HTML Requests to HTTPS
	log.Fatal(http.ListenAndServe(":80", http.HandlerFunc(bcnetgo.HTTPSRedirect)))
	/*
		// Serve HTTP HTML Requests
		log.Fatal(http.ListenAndServe(":80", nil))
	*/
}

func HandleAlias(w http.ResponseWriter, r *http.Request) {
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
		t, err := template.ParseFiles("html/template/alias.html")
		if err != nil {
			log.Println(err)
			return
		}
		data := struct {
			Alias     string
			PublicKey string
		}{
			Alias:     a,
			PublicKey: publicKey,
		}
		log.Println("Data", data)
		err = t.Execute(w, data)
		if err != nil {
			log.Println(err)
			return
		}
	case "POST":
		r.ParseForm()
		log.Println("Request", r)
		a := r.Form["alias"]
		log.Println("Alias", a)
		publicKey := r.Form["publicKey"]
		log.Println("PublicKey", publicKey)
		publicKeyFormat := r.Form["publicKeyFormat"]
		log.Println("PublicKeyFormat", publicKeyFormat)
		signature := r.Form["signature"]
		log.Println("Signature", signature)
		signatureAlgorithm := r.Form["signatureAlgorithm"]
		log.Println("SignatureAlgorithm", signatureAlgorithm)

		pubFormatValue, ok := bcgo.PublicKeyFormat_value[publicKeyFormat[0]]
		if !ok {
			log.Println("Unrecognized Public Key Format")
			return
		}
		pubFormat := bcgo.PublicKeyFormat(pubFormatValue)

		sig, err := base64.RawURLEncoding.DecodeString(signature[0])
		if err != nil {
			log.Println(err)
			return
		}

		sigAlgValue, ok := bcgo.SignatureAlgorithm_value[signatureAlgorithm[0]]
		if !ok {
			log.Println("Unrecognized Signature")
			return
		}
		sigAlg := bcgo.SignatureAlgorithm(sigAlgValue)

		record, err := aliasgo.CreateAliasRecord(a[0], []byte(publicKey[0]), pubFormat, sig, sigAlg)
		if err != nil {
			log.Println(err)
			return
		}

		data, err := proto.Marshal(record)
		if err != nil {
			log.Println(err)
			return
		}

		entries := [1]*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				RecordHash: bcgo.Hash(data),
				Record:     record,
			},
		}

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

		// Mine record into blockchain
		hash, block, err := node.Mine(aliases, entries[:])
		if err != nil {
			log.Println(err)
			return
		}
		node.Multicast(aliases, hash, block)
	default:
		log.Println("Unsupported method", r.Method)
	}
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
}

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
			Description: "Mining Service",
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

			customerReference, err := Mine(node, customers, acl, customerData)
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

			subscriptionReference, err := Mine(node, subscriptions, acl, subscriptionData)
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

func HandleUpload(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	request, err := spacego.ReadStorageRequest(reader)
	if err != nil {
		log.Println(err)
		return
	}

	timestamp := time.Now().Unix()

	size := proto.Size(request)
	log.Println("StorageRequest", size, request.Alias, request.CustomerId, request.PaymentId)

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
	publicKey, err := aliasgo.GetPublicKey(aliases, request.Alias)
	if err != nil {
		log.Println(err)
		return
	}

	if len(request.CustomerId) > 0 {
		// TODO check public key matches subscribed customer
		// TODO bill customer
		subscriptions, err := financego.OpenSubscriptionChannel()
		if err != nil {
			log.Println(err)
			return
		}
		subscription, err := financego.GetSubscriptionSync(subscriptions, node.Alias, node.Key, request.Alias)
		if err != nil {
			log.Println(err)
			return
		}
		if subscription.CustomerId != request.CustomerId {
			log.Println("Difference customer ID")
			return
		}
		stripeUsageRecord, bcUsageRecord, err := financego.NewUsageRecord(request.Alias, subscription.SubscriptionItemId, int64(timestamp), int64(size))
		if err != nil {
			log.Println(err)
			return
		}
		log.Println("UsageRecord", stripeUsageRecord)
		log.Println("UsageRecord", bcUsageRecord)
		// TODO Mine bcUsageRecord into UsageChannel
	} else if len(request.PaymentId) > 0 {
		stripeCharge, bcCharge, err := financego.NewCharge(request.Alias, request.PaymentId, int64(size), fmt.Sprintf("Aletheia Ware LLC Mining Charge %d at %d", size, timestamp))
		if err != nil {
			log.Println(err)
			return
		}
		log.Println("Charge", stripeCharge)
		log.Println("Charge", bcCharge)
		// TODO Mine bcCharge into ChargeChannel
	} else {
		log.Println("Missing payment information")
		// TODO if the user wants to subscribe, POST to :443/subscription with publicKey, and stripe info.
		// If response is success, await new head of Space Registration channel, and decrypt to get customer id.
		return
	}

	response := &spacego.StorageResponse{}

	// Create an array to hold at most two references (file, preview)
	references := make([]*bcgo.Reference, 0, 2)

	files, err := spacego.OpenFileChannel(request.Alias)
	if err != nil {
		log.Println(err)
		return
	}

	fileReference, err := MineBundle(node, files, request.Alias, publicKey, request.File, nil)
	if err != nil {
		log.Println(err)
		return
	}
	// Add fileReference to response
	response.File = fileReference
	// Add fileReference to list of references
	references = append(references, response.File)

	if request.Preview != nil {
		/* TODO
		previews, err := spacego.OpenPreviewChannel(request.Alias)
		if err != nil {
			log.Println(err)
			return
		}
		previewReference, err := MineBundle(node, previews, request.Alias, publicKey, request.Preview, nil)
		if err != nil {
			log.Println(err)
			return
		}
		// Add previewReference to response
		response.Preview = previewReference
		// Add previewReference to list of references
		references = append(references, response.Preview)
		*/
	}

	metas, err := spacego.OpenMetaChannel(request.Alias)
	if err != nil {
		log.Println(err)
		return
	}
	metaReference, err := MineBundle(node, metas, request.Alias, publicKey, request.Meta, references)
	if err != nil {
		log.Println(err)
		return
	}
	response.Meta = metaReference

	// Reply with storage response
	log.Println("StorageResponse", response)
	if err := spacego.WriteStorageResponse(writer, response); err != nil {
		log.Println(err)
		return
	}
}

func Mine(node *bcgo.Node, channel *bcgo.Channel, acl map[string]*rsa.PublicKey, data []byte) (*bcgo.Reference, error) {
	// Create record from server to acl
	record, err := bcgo.CreateRecord(node.Alias, node.Key, acl, nil, data)
	if err != nil {
		return nil, err
	}

	log.Println("Record", record)

	data, err = proto.Marshal(record)
	if err != nil {
		return nil, err
	}

	entries := [1]*bcgo.BlockEntry{
		&bcgo.BlockEntry{
			RecordHash: bcgo.Hash(data),
			Record:     record,
		},
	}

	// Mine record into blockchain
	hash, block, err := node.Mine(channel, entries[:])
	if err != nil {
		return nil, err
	}
	node.Multicast(channel, hash, block)
	return &bcgo.Reference{
		Timestamp:   block.Timestamp,
		ChannelName: channel.Name,
		BlockHash:   hash,
	}, nil
}

func MineBundle(node *bcgo.Node, channel *bcgo.Channel, alias string, publicKey *rsa.PublicKey, bundle *spacego.StorageRequest_Bundle, references []*bcgo.Reference) (*bcgo.Reference, error) {
	log.Println("Mining", channel.Name)
	if err := bcgo.VerifySignature(publicKey, bcgo.Hash(bundle.Payload), bundle.Signature, bundle.SignatureAlgorithm); err != nil {
		log.Println("Signature Verification Failed", err)
		return nil, err
	}

	timestamp := uint64(time.Now().UnixNano())

	recipients := [1]*bcgo.Record_Access{
		&bcgo.Record_Access{
			Alias:               alias,
			SecretKey:           bundle.Key,
			EncryptionAlgorithm: bundle.KeyEncryptionAlgorithm,
		},
	}

	// Create record
	record := &bcgo.Record{
		Timestamp:            timestamp,
		Creator:              alias,
		Access:               recipients[:],
		Payload:              bundle.Payload,
		CompressionAlgorithm: bundle.CompressionAlgorithm,
		EncryptionAlgorithm:  bundle.EncryptionAlgorithm,
		Signature:            bundle.Signature,
		SignatureAlgorithm:   bundle.SignatureAlgorithm,
		Reference:            references,
	}

	// Marshal into byte array
	data, err := proto.Marshal(record)
	if err != nil {
		return nil, err
	}

	// Get record hash
	hash := bcgo.Hash(data)

	// Create entry array containing hash and record
	entries := [1]*bcgo.BlockEntry{
		&bcgo.BlockEntry{
			RecordHash: hash,
			Record:     record,
		},
	}

	// Mine channel in goroutine
	go func() {
		_, _, err := node.Mine(channel, entries[:])
		if err != nil {
			log.Println(err)
			return
		}
	}()

	// Return reference to record
	return &bcgo.Reference{
		Timestamp:   timestamp,
		ChannelName: channel.Name,
		RecordHash:  hash,
	}, nil
}
