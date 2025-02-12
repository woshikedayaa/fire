package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
)

var (
	outputFormat string
	filterTmpl   string

	nftablesStatusCommand = &cobra.Command{
		Use:   "status",
		Short: "Check system firewall status",
		Long: `Check the status of system firewall implementations including:
- nftables installation and version
- iptables implementation type (legacy/nft)
- other firewall components status`,
		RunE: nftablesStatus,
	}
)

func init() {
	commandNftables.AddCommand(nftablesStatusCommand)
	nftablesStatusCommand.Flags().StringVar(&outputFormat, "format", "test", "Output format: text, json")
	nftablesStatusCommand.Flags().StringVar(&filterTmpl, "filter", "", "Go template filter for output")
}

func nftablesStatus(cmd *cobra.Command, args []string) error {
	data := collectStatusData()
	if filterTmpl != "" {
		tmpl, err := template.New("filter").Parse(filterTmpl)
		if err != nil {
			return fmt.Errorf("invalid template: %v", err)
		}
		return tmpl.Execute(os.Stdout, data)
	}

	// output
	switch outputFormat {
	case "json":
		return json.NewEncoder(os.Stdout).Encode(data)
	case "text":
		renderText(data)
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", outputFormat)
	}
}

type nftablesStatusData struct {
	Nftables struct {
		Installed bool   `json:"installed"`
		Version   string `json:"version"`
		Backend   string `json:"backend,omitempty"`  // nf_tables backend info
		Features  string `json:"features,omitempty"` // supported features
	} `json:"nftables"`
	Iptables struct {
		Type    string   `json:"type"`
		Version string   `json:"version"`
		Tables  []string `json:"tables,omitempty"` // loaded tables
		Chains  []string `json:"chains,omitempty"` // default chain
	} `json:"iptables"`
	Ebtables struct {
		Installed bool   `json:"installed"`
		Version   string `json:"version"`
		Type      string `json:"type"` // legacy/nft backend
	} `json:"ebtables"`
	Arptables struct {
		Installed bool   `json:"installed"`
		Version   string `json:"version"`
		Type      string `json:"type"` // legacy/nft backend
	} `json:"arptables"`
	KernelModules []string `json:"kernel_modules"`
	Firewall      struct {
		Type    string `json:"type"`
		Version string `json:"version"`
	} `json:"firewall"`
}

func getFirewallType() (string, string) {
	hasFirewalld := checkCommand("firewalld")
	hasUfw := checkCommand("ufw")

	var fwType string
	var version string

	switch {
	case hasFirewalld && hasUfw:
		fwType = "firewalld and ufw"
		version = getCommandVersion("firewalld")
	case hasFirewalld:
		fwType = "firewalld"
		version = getCommandVersion("firewalld")
	case hasUfw:
		fwType = "ufw"
		version = getCommandVersion("ufw")
	default:
		fwType = "not installed"
	}

	return fwType, version
}

func getLoadedKernelModules() []string {
	file, err := os.Open("/proc/modules")
	if err != nil {
		return nil
	}
	defer file.Close()

	var modules []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) > 0 {
			moduleName := fields[0]
			if strings.HasPrefix(moduleName, "nf_") ||
				strings.HasPrefix(moduleName, "nft_") ||
				strings.HasPrefix(moduleName, "ipt_") ||
				strings.HasPrefix(moduleName, "iptable_") ||
				strings.HasPrefix(moduleName, "ip6t_") ||
				strings.HasPrefix(moduleName, "ip6table_") ||
				strings.HasPrefix(moduleName, "ebt_") ||
				strings.HasPrefix(moduleName, "ebtable_") ||
				strings.HasPrefix(moduleName, "arpt_") ||
				strings.HasPrefix(moduleName, "arptable_") ||
				strings.Contains(moduleName, "netfilter") {
				modules = append(modules, moduleName)
			}
		}
	}

	return modules
}

func getIptablesInfo() (string, string, []string, []string) {
	implType := getIptablesType()
	version := getCommandVersion("iptables")

	var tables, chains []string

	cmd := exec.Command("iptables-save", "-c")
	out, err := cmd.CombinedOutput()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "*") {
				tables = append(tables, strings.TrimPrefix(line, "*"))
			} else if strings.HasPrefix(line, ":") {
				chain := strings.Fields(line)[0][1:]
				chains = append(chains, chain)
			}
		}
	}

	return implType, version, tables, chains
}

func getNftablesInfo() (bool, string, string, string) {
	if !checkCommand("nft") {
		return false, "", "", ""
	}

	version := getCommandVersion("nft")

	cmd := exec.Command("nft", "--check")
	out, _ := cmd.CombinedOutput()
	backend := ""
	if strings.Contains(string(out), "nf_tables") {
		backend = "nf_tables"
	}

	cmd = exec.Command("nft", "-v")
	out, _ = cmd.CombinedOutput()
	features := ""
	if strings.Contains(string(out), "debug") {
		features = "debug support"
	}

	return true, version, backend, features
}

func getEbtablesInfo() (bool, string, string) {
	if !checkCommand("ebtables") {
		return false, "", ""
	}

	version := getCommandVersion("ebtables")

	implType := "legacy"
	cmd := exec.Command("ebtables", "--version")
	out, _ := cmd.CombinedOutput()
	if strings.Contains(string(out), "nf_tables") {
		implType = "nf_tables"
	}

	return true, version, implType
}

func getArptablesInfo() (bool, string, string) {
	if !checkCommand("arptables") {
		return false, "", ""
	}

	version := getCommandVersion("arptables")

	implType := "legacy"
	cmd := exec.Command("arptables", "--version")
	out, _ := cmd.CombinedOutput()
	if strings.Contains(string(out), "nf_tables") {
		implType = "nf_tables"
	}

	return true, version, implType
}

func collectStatusData() nftablesStatusData {
	var data nftablesStatusData

	// nftables
	data.Nftables.Installed, data.Nftables.Version, data.Nftables.Backend, data.Nftables.Features = getNftablesInfo()

	// iptables
	data.Iptables.Type, data.Iptables.Version, data.Iptables.Tables, data.Iptables.Chains = getIptablesInfo()

	// ebtables
	data.Ebtables.Installed, data.Ebtables.Version, data.Ebtables.Type = getEbtablesInfo()

	// arptables
	data.Arptables.Installed, data.Arptables.Version, data.Arptables.Type = getArptablesInfo()

	data.KernelModules = getLoadedKernelModules()
	data.Firewall.Type, data.Firewall.Version = getFirewallType()

	return data
}

// checkCommand checks if a command exists in PATH
func checkCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// getCommandVersion attempts to get the version of a command
func getCommandVersion(name string) string {
	cmd := exec.Command(name, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "unknown"
	}
	return strings.Split(string(out), "\n")[0]
}

// getIptablesType determines the iptables implementation type
func getIptablesType() string {
	paths := []string{
		"/usr/sbin/iptables-legacy",
		"/usr/sbin/iptables-nft",
		"/sbin/iptables-legacy",
		"/sbin/iptables-nft",
	}

	var legacyExists, nftExists bool
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			if strings.Contains(path, "legacy") {
				legacyExists = true
			}
			if strings.Contains(path, "nft") {
				nftExists = true
			}
		}
	}

	// Check which implementation is currently active
	cmd := exec.Command("iptables", "-V")
	out, err := cmd.CombinedOutput()
	if err == nil {
		output := strings.ToLower(string(out))
		if strings.Contains(output, "nf_tables") {
			return "nf_tables backend (iptables-nft)"
		}
		if strings.Contains(output, "legacy") {
			return "legacy backend (iptables-legacy)"
		}
	}

	// Return based on existence
	switch {
	case legacyExists && nftExists:
		return "both implementations available"
	case legacyExists:
		return "legacy only"
	case nftExists:
		return "nft only"
	default:
		return "not found"
	}
}
func renderText(data nftablesStatusData) {
	nftStatus := "not installed"
	if data.Nftables.Installed {
		nftStatus = fmt.Sprintf("installed (version: %s)", data.Nftables.Version)
		if data.Nftables.Backend != "" {
			nftStatus += fmt.Sprintf(", backend: %s", data.Nftables.Backend)
		}
		if data.Nftables.Features != "" {
			nftStatus += fmt.Sprintf(", features: %s", data.Nftables.Features)
		}
	}
	fmt.Printf("nftables\t: %s\n", nftStatus)

	iptStatus := data.Iptables.Type
	if iptStatus != "not installed" {
		iptStatus = fmt.Sprintf("%s (version: %s)", iptStatus, data.Iptables.Version)
		if len(data.Iptables.Tables) > 0 {
			iptStatus += fmt.Sprintf(", tables: %s", strings.Join(data.Iptables.Tables, ","))
		}
	}
	fmt.Printf("iptables\t: %s\n", iptStatus)

	ebtStatus := "not installed"
	if data.Ebtables.Installed {
		ebtStatus = fmt.Sprintf("installed (version: %s, type: %s)",
			data.Ebtables.Version, data.Ebtables.Type)
	}
	fmt.Printf("ebtables\t: %s\n", ebtStatus)

	arpStatus := "not installed"
	if data.Arptables.Installed {
		arpStatus = fmt.Sprintf("installed (version: %s, type: %s)",
			data.Arptables.Version, data.Arptables.Type)
	}
	fmt.Printf("arptables\t: %s\n", arpStatus)

	fmt.Print("kernel_modules\t: ")
	if len(data.KernelModules) > 0 {
		fmt.Println(strings.Join(data.KernelModules, ", "))
	} else {
		fmt.Println("none")
	}

	fwStatus := data.Firewall.Type
	if fwStatus != "not installed" && data.Firewall.Version != "" {
		fwStatus = fmt.Sprintf("%s (version: %s)", fwStatus, data.Firewall.Version)
	}
	fmt.Printf("firewall\t: %s\n", fwStatus)
}
