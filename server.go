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
	"path"
	"time"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	// Serve Block Requests
	go bcnetgo.Bind(bcgo.PORT_BLOCK, bcnetgo.HandleBlock)
	// Serve Head Requests
	go bcnetgo.Bind(bcgo.PORT_HEAD, bcnetgo.HandleHead)
	// Serve Upload Requests
	go bcnetgo.Bind(spacego.PORT_UPLOAD, HandleUpload)

	// Serve Web Requests
	mux := http.NewServeMux()
	mux.HandleFunc("/", bcnetgo.HandleStatic)
	mux.HandleFunc("/stripe-webhook", HandleStripeWebhook)
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

			customerReference, err := node.Mine(customers, acl, customerData)
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

			subscriptionReference, err := node.Mine(subscriptions, acl, subscriptionData)
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

	fileReference, err := spacego.MineBundle(node, files, request.Alias, publicKey, request.File, nil)
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
		previewReference, err := spacego.MineBundle(node, previews, request.Alias, publicKey, request.Preview, nil)
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
	metaReference, err := spacego.MineBundle(node, metas, request.Alias, publicKey, request.Meta, references)
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
