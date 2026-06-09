package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alpha-omega-security/marshal/internal/db"
	enrichpkgs "github.com/alpha-omega-security/marshal/internal/enrich/packages"
	"github.com/alpha-omega-security/marshal/internal/ingest"
	"github.com/alpha-omega-security/marshal/internal/web"
)

const defaultDB = "marshal.db"

func usage() {
	fmt.Fprintf(os.Stderr, `marshal - local package data lake

Usage:
  marshal load <path>          load SBOM (CycloneDX or SPDX) from file
  marshal load -               load SBOM from stdin
  marshal enrich [--only-stale] hit packages.ecosyste.ms for each package
  marshal serve [--addr ADDR]  start the web UI

Flags:
  --db PATH                    SQLite path (default: ./marshal.db)
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "load":
		runLoad(args)
	case "enrich":
		runEnrich(args)
	case "serve":
		runServe(args)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func runLoad(args []string) {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "SQLite path")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		log.Fatal("usage: marshal load <path|->")
	}

	g, err := db.Open(*dbPath)
	if err != nil {
		log.Fatal(err)
	}

	inserted, existing, err := ingest.LoadFile(g, fs.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("loaded: %d new, %d already known\n", inserted, existing)
}

func runEnrich(args []string) {
	fs := flag.NewFlagSet("enrich", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "SQLite path")
	onlyStale := fs.Bool("only-stale", false, "skip packages enriched within the freshness window")
	staleDays := fs.Int("stale-days", 7, "freshness window in days when --only-stale is set")
	_ = fs.Parse(args)

	g, err := db.Open(*dbPath)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	updated, err := enrichpkgs.Enrich(ctx, g, *onlyStale, time.Duration(*staleDays)*24*time.Hour)
	if err != nil {
		cancel()
		log.Fatal(err)
	}
	fmt.Printf("enriched: %d packages\n", updated)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "SQLite path")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	_ = fs.Parse(args)

	g, err := db.Open(*dbPath)
	if err != nil {
		log.Fatal(err)
	}

	srv, err := web.NewServer(g)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("marshal serving at http://%s\n", *addr)
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
