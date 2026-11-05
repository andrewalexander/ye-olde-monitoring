package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
)

// backup writes a timestamped copy of the database into a directory and
// keeps the newest -keep copies. Safe to run while serve/ingest are writing.
func backup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	db := dbFlag(fs)
	keep := fs.Int("keep", 7, "how many backups to keep (0 keeps all)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: dnscount backup [-db path] [-keep n] <dir>")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	dir := fs.Arg(0)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	st, err := store.Open(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	dest := filepath.Join(dir, "dnscount-"+time.Now().Format("20060102-150405")+".db")
	if err := st.Backup(dest); err != nil {
		return fmt.Errorf("backup to %s: %w", dest, err)
	}
	fmt.Println(dest)
	if *keep <= 0 {
		return nil
	}
	old, _ := filepath.Glob(filepath.Join(dir, "dnscount-*.db"))
	sort.Strings(old) // timestamped names sort oldest first
	for len(old) > *keep {
		os.Remove(old[0])
		old = old[1:]
	}
	return nil
}
