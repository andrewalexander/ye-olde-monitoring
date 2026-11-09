// Command app is a tiny site that is NOT behind Caddy, so nothing logs its
// requests for it: middleware.Wrap records each one instead, either shipping
// it to `dnscount serve` or writing it straight to the database:
//
//	go run ./examples/app -collector http://localhost:8080/ingest -token t   # RemoteSink
//	go run ./examples/app -db app.db                                         # LocalSink
//
// Behind Caddy, skip all of this and serve files (see examples/caddy-site).
// Its counter image comes from wherever `dnscount serve` is reachable
// (-counter), and counts the page loads the middleware recorded.
package main

import (
	"embed"
	"flag"
	"html/template"
	"io/fs"
	"log"
	"net/http"

	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
	"github.com/andrewalexander/ye-olde-monitoring/middleware"
)

//go:embed site
var siteFS embed.FS

func main() {
	addr := flag.String("addr", ":8000", "listen address")
	collector := flag.String("collector", "", "collector /ingest URL (RemoteSink)")
	token := flag.String("token", "", "collector token")
	db := flag.String("db", "", "local SQLite path (LocalSink), used if -collector is empty")
	counterURL := flag.String("counter", "http://localhost:8080", "where dnscount serve's /counter.svg is reachable from a browser")
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

	site, _ := fs.Sub(siteFS, "site")
	index := template.Must(template.ParseFS(site, "index.html"))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		index.Execute(w, map[string]string{"Counter": *counterURL + "/counter.svg?site=example"})
	})
	mux.Handle("GET /", http.FileServerFS(site))
	mux.HandleFunc("GET /healthz",func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })

	h := middleware.Wrap(mux, sink, middleware.Options{Site: "example", SkipPaths: []string{"/healthz"}})
	log.Printf("example app on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, h))
}
