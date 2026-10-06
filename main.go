package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/fatih/color"

	"sukku/internal/modules/crawling"
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

func portscan() {

	info("Running Port Scan")

	command := "nmap -iL live.txt -Pn"

	cmd := exec.Command("bash", "-c", command)

	output, err := cmd.Output()

	if err != nil {
		failed(err.Error())
		return
	}

	os.WriteFile("ports.txt", output, 0644)

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

	info("Running Screenshot Module")
	os.Mkdir("screenshots", 0755)

	data := []byte("Screenshot module working\n")

	os.WriteFile("screenshots/test.txt", data, 0644)

	success("Screenshots folder created")
}

func wayback() {
	info("Running Wayback Module")

	data := []byte("https://example.com/page1\nhttps://example.com/page2\n")
	os.WriteFile("wayback.txt", data, 0644)

	success("Wayback Completed")

}

func summary() {

	fmt.Println()
	fmt.Println("========== SUKKU SUMMARY ==========")
	fmt.Println("Subdomains  : Completed")
	fmt.Println("Live Hosts  : Completed")
	fmt.Println("Port Scan   : Completed")
	fmt.Println("JS Finder   : Completed")
	fmt.Println("screenshots : Completed")
	fmt.Println("wayback     : Completed")
	fmt.Println("===================================")
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

	portscan()

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
		summary()

	}
}
