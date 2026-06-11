package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/fatih/color"
)

var (
<<<<<<< HEAD
	version = "v1.1.0"

        white = color.New(...)
)

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

func subfinder(domain string) {

	info("Running Subfinder")

	cmd := exec.Command("subfinder", "-d", domain, "-silent")

	output, err := cmd.Output()

	if err != nil {
		failed(err.Error())
		return
	}

	os.WriteFile("subdomains.txt", output, 0644)

	success("Subdomains saved in subdomains.txt")
}

func httpx() {

	info("Running HTTPX")

	command := "cat subdomains.txt | httpx -silent"

	cmd := exec.Command("bash", "-c", command)

	output, err := cmd.Output()

	if err != nil {
		failed(err.Error())
		return
	}

	os.WriteFile("live.txt", output, 0644)

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

func nuclei() {

	info("Running Nuclei Scan")

	command := "cat live.txt | nuclei -silent"

	cmd := exec.Command("bash", "-c", command)

	output, err := cmd.Output()

	if err != nil {
		failed(err.Error())
		return
	}

	os.WriteFile("nuclei.txt", output, 0644)

	success("Nuclei results saved in nuclei.txt")
}

func jsfinder() {

	info("Running JS Finder")

	command := "cat live.txt | katana -silent | grep '.js' || true"
	cmd := exec.Command("bash", "-c", command)

	output, err := cmd.Output()

	if err != nil {
		failed(err.Error())
		return
	}

	os.WriteFile("jsfiles.txt", output, 0644)

	success("JS files saved in jsfiles.txt")
}

<<<<<<< HEAD
=======
func screenshots() {

	info("Running Screenshot Module")
	os.Mkdir("screenshots", 0755)

        data := []byte("Screenshot module working\n")


        os.WriteFile("screenshots/test.txt", data,0644)


	success("Screenshots folder created")
}

>>>>>>> bee20b6 (Initial commit - sukku v1.1.0)
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
<<<<<<< HEAD
=======
        fmt.Println(white(" --screenshots       Website screenshots"))
        fmt.Println(white(" --wayback           Historical URLs"))
>>>>>>> bee20b6 (Initial commit - sukku v1.1.0)
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

<<<<<<< HEAD
=======
        enableScreenshots := flag.Bool("screenshots", false, "Website screenshots")
        enableWayback := flag.Bool("wayback", false, "Historical URLs")

>>>>>>> bee20b6 (Initial commit - sukku v1.1.0)
	flag.Usage = func() {
		helpmenu()
	}

	banner()

	domain := flag.String("d", "", "Target Domain")

	flag.Parse()

<<<<<<< HEAD
	if *showVersion {
		fmt.Println(green("Sukku " + version))
		return
	}

	if *domain == "" {
		helpmenu()
		return
	}
=======
        if *showVersion {
         fmt.Println(green("Sukku " + version))
         return

        }

        if *enableScreenshots {
	  screenshots()

        }


        if *enableWayback {
          fmt.Println("Wayback enable")

        }

        if *domain == "" {
          helpmenu()
          return

        }
>>>>>>> bee20b6 (Initial commit - sukku v1.1.0)

	subfinder(*domain)

	httpx()

	portscan()

	nuclei()

	jsfinder()

	success("Sukku Scan Completed")
<<<<<<< HEAD
}
=======

       }
>>>>>>> bee20b6 (Initial commit - sukku v1.1.0)
