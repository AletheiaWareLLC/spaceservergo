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
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/netgo"
	"github.com/AletheiaWareLLC/spacego"
	"html/template"
	"log"
	"math"
	"net/http"
)

func RegistrarHandler(template *template.Template, get func(string) (*spacego.Registrar, error)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RemoteAddr, r.Proto, r.Method, r.Host, r.URL.Path)
		switch r.Method {
		case "GET":
			registrar := netgo.GetQueryParameter(r.URL.Query(), "registrar")
			log.Println("Registrar", registrar)
			if len(registrar) > 0 {
				r, err := get(registrar)
				if err != nil {
					log.Println(err)
					return
				}
				data := struct {
					Alias        string
					Domain       string
					Country      string
					Currency     string
					GroupPrice   string
					GroupSize    string
					Interval     string
					Mode         string
					CostExamples [][]string
				}{
					Alias:        r.Merchant.Alias,
					Domain:       r.Merchant.Domain,
					Country:      r.Service.Country,
					Currency:     r.Service.Currency,
					GroupPrice:   bcgo.MoneyToString(r.Service.Currency, r.Service.GroupPrice),
					GroupSize:    bcgo.DecimalSizeToString(uint64(r.Service.GroupSize)),
					Interval:     r.Service.Interval.String(),
					Mode:         r.Service.Mode.String(),
					CostExamples: make([][]string, 0),
				}
				for _, s := range []uint64{
					0,
					1234,
					800000000,
					28000000000,
					564000000000,
					1200000000000,
				} {
					data.CostExamples = append(data.CostExamples, []string{
						bcgo.DecimalSizeToString(s),
						bcgo.MoneyToString(r.Service.Currency, int64(math.Ceil(float64(s)/float64(r.Service.GroupSize)))*r.Service.GroupPrice),
					})
				}
				err = template.Execute(w, data)
				if err != nil {
					log.Println(err)
					return
				}
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		default:
			log.Println("Unsupported method", r.Method)
		}
	}
}

func RegistrarListHandler(template *template.Template, list func() []*spacego.Registrar) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RemoteAddr, r.Proto, r.Method, r.Host, r.URL.Path)
		switch r.Method {
		case "GET":
			type TemplateRegistrar struct {
				Alias    string
				Domain   string
				Country  string
				Currency string
				Cost     string
			}
			registrars := make([]*TemplateRegistrar, 0)
			for _, registrar := range list() {
				registrars = append(registrars, &TemplateRegistrar{
					Alias:    registrar.Merchant.Alias,
					Domain:   registrar.Merchant.Domain,
					Country:  registrar.Service.Country,
					Currency: registrar.Service.Currency,
					Cost:     bcgo.MoneyToString(registrar.Service.Currency, registrar.Service.GroupPrice) + "/" + bcgo.DecimalSizeToString(uint64(registrar.Service.GroupSize)),
				})
			}
			data := struct {
				Registrar []*TemplateRegistrar
			}{
				Registrar: registrars,
			}
			if err := template.Execute(w, data); err != nil {
				log.Println(err)
				return
			}
		default:
			log.Println("Unsupported method", r.Method)
		}
	}
}
