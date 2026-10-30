package main

import (
	"flag"
	"log"

	"domain-analyzer/storage"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

func main() {
	var dbPath string
	flag.StringVar(&dbPath, "db", "", "Optional custom SQLite database file path")
	flag.Parse()

	if dbPath == "" {
		var err error
		dbPath, err = storage.DefaultDBPath()
		if err != nil {
			log.Fatalf("Failed to determine database path: %v", err)
		}
	}

	store, err := storage.Open(dbPath)
	if err != nil {
		log.Fatalf("Failed to open SQLite store (%s): %v", dbPath, err)
	}
	defer store.Close()

	app := NewDesktopApp(store)

	// If a target domain or IP was passed on the command line when launching the GUI,
	// pre-populate it and start scanning once ready.
	initialTarget := ""
	if flag.NArg() > 0 {
		initialTarget = flag.Arg(0)
		app.targetInput = initialTarget
	}

	mygo.App.WhenReady(func() {
		win := mygo.NewWindow(mygo.WindowOptions{
			Title:    "Domain Analyzer — Reconnaissance & Pivot Explorer",
			Width:    1280,
			Height:   820,
			StateKey: "domain-analyzer-main",
			Content:  ui.View(app.View),
		})
		app.SetWindow(win)

		if initialTarget != "" {
			app.StartScan(initialTarget, 0, "CLI Launch")
		}
	})

	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
