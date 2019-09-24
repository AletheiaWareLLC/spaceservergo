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
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/bcnetgo"
	"github.com/AletheiaWareLLC/spacego"
	"html/template"
	"log"
	"math"
	"net/http"
)

func MinerHandler(template *template.Template, get func(string) (*spacego.Miner, error)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RemoteAddr, r.Proto, r.Method, r.Host, r.URL.Path)
		switch r.Method {
		case "GET":
			miner := bcnetgo.GetQueryParameter(r.URL.Query(), "miner")
			log.Println("Miner", miner)
			if len(miner) > 0 {
				m, err := get(miner)
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
					Alias:        m.Merchant.Alias,
					Domain:       m.Merchant.Domain,
					Country:      m.Service.Country,
					Currency:     m.Service.Currency,
					GroupPrice:   bcgo.MoneyToString(m.Service.Currency, m.Service.GroupPrice),
					GroupSize:    bcgo.DecimalSizeToString(uint64(m.Service.GroupSize)),
					Interval:     m.Service.Interval.String(),
					Mode:         m.Service.Mode.String(),
					CostExamples: make([][]string, 0),
				}
				for _, s := range []uint64{
					0,
					1234,
					800000,
					28000000,
					564000000,
					1200000000,
				} {
					data.CostExamples = append(data.CostExamples, []string{
						bcgo.DecimalSizeToString(s),
						bcgo.MoneyToString(m.Service.Currency, int64(math.Ceil(float64(s)/float64(m.Service.GroupSize)))*m.Service.GroupPrice),
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

func MinerListHandler(template *template.Template, list func() []*spacego.Miner) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RemoteAddr, r.Proto, r.Method, r.Host, r.URL.Path)
		switch r.Method {
		case "GET":
			type TemplateMiner struct {
				Alias    string
				Domain   string
				Country  string
				Currency string
				Cost     string
			}
			miners := make([]*TemplateMiner, 0)
			for _, miner := range list() {
				miners = append(miners, &TemplateMiner{
					Alias:    miner.Merchant.Alias,
					Domain:   miner.Merchant.Domain,
					Country:  miner.Service.Country,
					Currency: miner.Service.Currency,
					Cost:     bcgo.MoneyToString(miner.Service.Currency, miner.Service.GroupPrice) + "/" + bcgo.DecimalSizeToString(uint64(miner.Service.GroupSize)),
				})
			}
			data := struct {
				Miner []*TemplateMiner
			}{
				Miner: miners,
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
