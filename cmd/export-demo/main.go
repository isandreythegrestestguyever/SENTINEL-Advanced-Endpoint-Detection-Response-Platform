package main

import (
	"encoding/json"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/detection"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/simulator"
	"os"
)

func main() {
	sigmaEngine, err := detection.DefaultSigmaEngine()
	if err != nil {
		panic(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"rules": detection.AllRules(sigmaEngine), "scenarios": simulator.All()}); err != nil {
		panic(err)
	}
}
