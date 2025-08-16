package main

import (
	"encoding/json"
	"github.com/joshdail/go_lan_scanner/network"
	"github.com/joshdail/go_lan_scanner/scanner"
	"log"
	"net/http"
)

func scanHandler(w http.ResponseWriter, r *http.Request) {
	info, err := network.GetDefaultInterface()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	devices, err := scanner.ARPScan(info.InterfaceName, info.CIDR)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devices)
}

func infoHandler(w http.ResponseWriter, r *http.Request) {
	info, err := network.GetDefaultInterface()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func updateOUIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := scanner.UpdateOUIDatabase("data/oui.csv"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("OUI database updated successfully\n"))
}

func main() {
	http.HandleFunc("/info", infoHandler)
	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/update_oui", updateOUIHandler)

	log.Println("Server listening on :8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
