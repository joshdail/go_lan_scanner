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
	json.NewEncoder(w).Encode(devices)
} // scanHandler

func infoHandler(w http.ResponseWriter, r *http.Request) {
	info, err := network.GetDefaultInterface()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(info)
} // infoHandler

func main() {
	http.HandleFunc("/info", infoHandler)
	http.HandleFunc("/scan", scanHandler)
	log.Println("Server listening on :8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
} // main
