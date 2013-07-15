package main

import (
	"errors"
	"fmt"
	"github.com/adpalmer/simple-auth"
	"github.com/hoisie/web"
	"log"
	"net/http"
	"time"
)

type Store struct {
	priv string
	data interface{}
}

func NewDb() *Db {
	return &Db{make(map[string]interface{})}
}

type Db struct {
	data map[string]interface{}
}

// set public key, private key and data
func (d *Db) Set(pub, priv string, data interface{}) error {
	d.data[pub] = Store{priv, data}
	return nil
}

// get public key, private key and data given a public key
func (d *Db) Get(pub string) (string, string, interface{}, error) {
	tmp, ok := d.data[pub]
	if ok == false {
		return "", "", nil, errors.New("Pub key doesn't exist")
	}
	r, _ := tmp.(Store)
	return pub, r.priv, r.data, nil
}

func main() {
	db := NewDb()
	prod := simpleAuth.NewProvider(db, 10, 20)

	pub, priv, _, _ := prod.Create("TEST data")
	fmt.Println("public key: ", pub)
	fmt.Println("private key: ", priv)

	go getTest(pub, priv)

	web.Get("/(.*)", testServer(prod))
	web.Run(":9999")
}

func testServer(prod *simpleAuth.Provider) func(*web.Context, string) {
	return func(ctx *web.Context, val string) {
		if val == "" {
			data, err := prod.Verify(ctx.Params["pubKey"], ctx.Params["data"], ctx.Params["signature"])
			if err != nil {
				log.Println(err)
				ctx.WriteString(fmt.Sprintln(err))
				ctx.WriteString("Signature rejected")
				return
			}
			ctx.WriteString("Signature accepted")
			log.Println("Auth Data: ", data)
		}
	}
}

func getTest(pub, priv string) {
	time.Sleep(100 * time.Millisecond)
	consumer := simpleAuth.NewConsumer(priv)
	data := "This_is_a_test"
	dataMOC := consumer.Encode(data)
	url := "http://localhost:9999/?pubKey=" + pub + "&data=" + data + "&signature=" + dataMOC
	log.Println("url: ", url)
	resp, err := http.Get(url)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
}
