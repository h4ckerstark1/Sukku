package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/fatih/color"

	"sukku/internal/modules/crawling"
	"sukku/internal/modules/ports"
	"sukku/internal/modules/probing"
	"sukku/internal/modules/subdomains"
	"sukku/internal/modules/vulnerability"

	"sukku/internal/store"
)

var (
	version = "v1.2.0"

	white  = color.New(color.FgHiWhite).SprintFunc()
	red    = color.New(color.FgHiRed).SprintFunc()
	blue   = color.New(color.FgHiBlue).SprintFunc()
	green  = color.New(color.FgHiGreen).SprintFunc()
	yellow = color.New(color.FgHiYellow).SprintFunc()
)

func banner() {

	banner := white(`

███████╗██╗   ██╗██╗  ██╗██╗  ██╗██╗   ██╗
██╔════╝██║   ██║██║ ██╔╝██║ ██╔╝██║   ██║
███████╗██║   ██║█████╔╝ █████╔╝ ██║   ██║
╚════██║██║   ██║██╔═██╗ ██╔═██╗ ██║   ██║
███████║╚██████╔╝██║  ██╗██║  ██╗╚██████╔╝
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝

`)

	fmt.Println(banner)

	fmt.Println(blue("         Sukku Recon Framework"))
	fmt.Println(white("                By Ayush Sharma"))
	fmt.Println(green("              Version " + version))
	fmt.Println()
}

func info(msg string) {
	fmt.Println(blue("[INFO]"), white(msg))
}

func success(msg string) {
	fmt.Println(green("[SUCCESS]"), white(msg))
}

func failed(msg string) {
	fmt.Println(red("[ERROR]"), white(msg))
}

func subfinder(domain string, assetStore *store.AssetStore) {
	info("Running Subfinder")

	cfg := subdomains.Config{
		Domain:         domain,
		SubfinderRaw:   "raw/subfinder.raw",
		SubdomainsFile: "subdomains.txt",
	}

	if err := subdomains.Run(context.Background(), cfg, assetStore); err != nil {
		failed(err.Error())
		return
	}

	success("Subdomains saved in subdomains.txt")
}

func httpx(assetStore *store.AssetStore) {

	info("Running HTTPX")

	cfg := probing.Config{
		SubdomainsFile: "subdomains.txt",
		HTTPXRaw:       "raw/httpx.raw",
		LiveFile:       "live.txt",
	}

	if err := probing.Run(context.Background(), cfg, assetStore); err != nil {
		failed(err.Error())
		return
	}

	success("Live domains saved in live.txt")
}

func portscan(assetStore *store.AssetStore) {

	info("Running Port Scan")

	cfg := ports.Config{
		PortscanRaw: "raw/portscan.raw",
		PortsFile:   "ports.txt",
	}

	if err := ports.Run(context.Background(), cfg, assetStore); err != nil {
		failed(err.Error())
		return
	}

	success("Port scan saved in ports.txt")
}

func nuclei(assetStore *store.AssetStore) {
	info("Running Nuclei Scan")

	cfg := vulnerability.Config{
		LiveFile:   "live.txt",
		NucleiRaw:  "raw/nuclei.raw",
		NucleiFile: "nuclei.txt",
	}

	if err := vulnerability.Run(context.Background(), cfg, assetStore); err != nil {
		failed(err.Error())
		return
	}

	success("Nuclei results saved in nuclei.txt")
}

func jsfinder(assetStore *store.AssetStore) {
	info("Running JS Finder")

	cfg := crawling.Config{
		LiveFile:    "live.txt",
		KatanaRaw:   "raw/katana.raw",
		JSFilesFile: "jsfiles.txt",
	}

	if err := crawling.Run(context.Background(), cfg, assetStore); err != nil {
		failed(err.Error())
		return
	}

	success("JS files saved in jsfiles.txt")
}

func screenshots() {
	fmt.Println(yellow("[WARN]"), white("Screenshot module is not implemented yet."))
}

func wayback() {
	fmt.Println(yellow("[WARN]"), white("Wayback module is not implemented yet."))
}

func summary(assetStore *store.AssetStore) {

	fmt.Println()
	fmt.Println("========== SUKKU SUMMARY ==========")
	fmt.Printf("Subdomains    : %d\n", len(assetStore.Domains()))
	fmt.Printf("Web Endpoints : %d\n", len(assetStore.WebEndpoints()))
	fmt.Printf("Services      : %d\n", len(assetStore.Services()))
	fmt.Printf("JS Files      : %d\n", len(assetStore.JSFiles()))
	fmt.Printf("Findings      : %d\n", len(assetStore.Findings()))
	fmt.Println("====================================")
}

func helpmenu() {

	fmt.Println(yellow("TARGET OPTIONS:"))
	fmt.Println()

	fmt.Println(white("  -d domain.tld      Target domain"))
	fmt.Println(white("  -l list.txt        Target list"))
	fmt.Println()

	fmt.Println(yellow("SCAN OPTIONS:"))
	fmt.Println()

	fmt.Println(white("  -subs              Subdomain scan"))
	fmt.Println(white("  -httpx             Live host detection"))
	fmt.Println(white("  -portscan          Port scanning"))
	fmt.Println(white("  -nuclei            Vulnerability scan"))
	fmt.Println(white("  -jsfinder          JavaScript file finder"))
	fmt.Println(white(" --screenshots       Website screenshots"))
	fmt.Println(white(" --wayback           Historical URLs"))
	fmt.Println()

	fmt.Println(yellow("GENERAL OPTIONS:"))
	fmt.Println()

	fmt.Println(white("  -h                 Show help menu"))
	fmt.Println(white("  -v                 Show version"))
	fmt.Println()

	fmt.Println(yellow("EXAMPLES:"))
	fmt.Println()

	fmt.Println(white("  ./sukku -d hackerone.com"))
	fmt.Println(white("  ./sukku -d target.com"))
	fmt.Println()
}
func main() {
	showVersion := flag.Bool("v", false, "Show Version")

	enableScreenshots := flag.Bool("screenshots", false, "Website screenshots")
	enableWayback := flag.Bool("wayback", false, "Historical URLs")
	enableSummary := flag.Bool("summary", false, "Show scan summary")

	flag.Usage = func() {
		helpmenu()
	}

	banner()

	domain := flag.String("d", "", "Target Domain")

	flag.Parse()

	if *showVersion {
		fmt.Println(green("Sukku " + version))
		return
	}

	if *domain == "" {
		helpmenu()
		return
	}

	assetStore := store.NewAssetStore()

	subfinder(*domain, assetStore)

	httpx(assetStore)

	portscan(assetStore)

	nuclei(assetStore)

	jsfinder(assetStore)

	if *enableScreenshots {
		screenshots()
	}

	if *enableWayback {
		wayback()
	}

	success("Sukku Scan Completed")

	if *enableSummary {
		summary(assetStore)

	}
}
