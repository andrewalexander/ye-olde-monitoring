// Command app is a tiny site showing both ways to use dnscount from Go:
//
//	go run ./examples/app -collector http://localhost:8080/ingest -token t   # ship hits to `dnscount serve`
//	go run ./examples/app -db app.db                                         # write hits locally
//
// The page also embeds the public counter from the collector.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"dnscount/middleware"
	"dnscount/store"
)

func main() {
	addr := flag.String("addr", ":8000", "listen address")
	collector := flag.String("collector", "", "collector /ingest URL (RemoteSink)")
	token := flag.String("token", "", "collector token")
	db := flag.String("db", "", "local SQLite path (LocalSink), used if -collector is empty")
	counterURL := flag.String("counter", "http://localhost:8080", "where counter.js is served")
	flag.Parse()

	var sink interface {
		middleware.Sink
		Close()
	}
	switch {
	case *collector != "":
		sink = middleware.NewRemoteSink(*collector, *token)
	case *db != "":
		st, err := store.Open(*db)
		if err != nil {
			log.Fatal(err)
		}
		defer st.Close()
		sink = middleware.NewLocalSink(st)
	default:
		log.Fatal("need -collector or -db")
	}
	defer sink.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<!doctype html><title>example</title><h1>hello</h1>
<p>you are visitor <script src="%s/counter.js" data-site="example"></script></p>`, *counterURL)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })

	h := middleware.Wrap(mux, sink, middleware.Options{Site: "example", SkipPaths: []string{"/healthz"}})
	log.Printf("example app on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, h))
}
