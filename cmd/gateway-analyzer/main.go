package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"gateway-module-analyzer/internal/analyze"
)

var version = "dev"
var releaseRepo = "a8848504/gateway-module-analyzer"

func cli(args []string) error {
	f := flag.NewFlagSet("gateway-analyzer", flag.ContinueOnError)
	raw := f.String("raw", "", "read a saved ETHE TCP stream")
	pcap := f.String("pcap", "", "read a PCAP or PCAPNG file")
	port := f.Uint("port", 7115, "positioning server TCP port")
	showVersion := f.Bool("version", false, "print version")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if (*raw == "") == (*pcap == "") || *port == 0 || *port > 65535 {
		return fmt.Errorf("specify --raw or --pcap and a valid TCP port")
	}
	filename := *raw
	if *pcap != "" {
		filename = *pcap
	}
	source, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer source.Close()
	var report *analyze.Report
	if *pcap != "" {
		report, err = analyze.ReadCapture(context.Background(), source, uint16(*port), nil)
	} else {
		report, err = analyze.ReadStream(source)
	}
	if err != nil {
		return err
	}
	output := json.NewEncoder(os.Stdout)
	output.SetIndent("", "  ")
	return output.Encode(report)
}
