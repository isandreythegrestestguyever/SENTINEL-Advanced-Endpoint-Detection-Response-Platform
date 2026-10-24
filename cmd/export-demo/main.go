package main

import (
	"encoding/json"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/detection"
	"github.com/isandreythegrestestguyever/SENTINEL-Advanced-Endpoint-Detection-Response-Platform/internal/simulator"
	"os"
)

func main() {
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"rules": detection.Rules, "scenarios": simulator.All()}); err != nil {
		panic(err)
	}
}
