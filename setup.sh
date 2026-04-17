#!/bin/bash
# ============================================================
# ReconAI - Tool Setup Script
# Installs all required recon tools on Linux (Debian/Ubuntu)
# Run: chmod +x setup.sh && sudo ./setup.sh
# ============================================================

set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ █████╗ ██╗"
echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║"
echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████║██║"
echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██║██║"
echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██║██║"
echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝"
echo -e "  ReconAI — Tool Setup${NC}"
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS="unknown"
fi

# ── System Dependencies ────────────────────────────────────────
echo -e "${YELLOW}[*] Installing system dependencies...${NC}"
if [[ "$OS" == "ubuntu" || "$OS" == "debian" || "$OS" == "kali" ]]; then
    apt-get update -qq
    apt-get install -y -qq \
        git curl wget unzip \
        python3 python3-pip python3-venv \
        nmap chromium \
        dnsutils net-tools \
        build-essential
elif [[ "$OS" == "arch" || "$OS" == "manjaro" ]]; then
    pacman -Sy --noconfirm git curl wget unzip python python-pip nmap chromium
fi

# ── Go Installation ────────────────────────────────────────────
echo -e "${YELLOW}[*] Checking Go installation...${NC}"
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}[*] Installing Go 1.22...${NC}"
    GO_VERSION="1.22.3"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    echo -e "${GREEN}[+] Go installed${NC}"
else
    echo -e "${GREEN}[+] Go already installed: $(go version)${NC}"
fi

export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# ── Go-based Recon Tools ───────────────────────────────────────
echo -e "${YELLOW}[*] Installing Go recon tools...${NC}"

install_go_tool() {
    local tool=$1
    local install_path=$2
    if command -v "$tool" &> /dev/null; then
        echo -e "${GREEN}[+] $tool already installed${NC}"
    else
        echo -e "${CYAN}[*] Installing $tool...${NC}"
        go install "$install_path" 2>/dev/null && \
            echo -e "${GREEN}[+] $tool installed${NC}" || \
            echo -e "${RED}[-] Failed to install $tool${NC}"
    fi
}

install_go_tool "subfinder"    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "httpx"        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "dnsx"         "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "katana"       "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "assetfinder"  "github.com/tomnomnom/assetfinder@latest"
install_go_tool "gau"          "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool "waybackurls"  "github.com/tomnomnom/waybackurls@latest"
install_go_tool "gowitness"    "github.com/sensepost/gowitness@latest"
install_go_tool "ffuf"         "github.com/ffuf/ffuf/v2@latest"
install_go_tool "trufflehog"   "github.com/trufflesecurity/trufflehog/v3@latest"
install_go_tool "gitleaks"     "github.com/gitleaks/gitleaks/v8@latest"
install_go_tool "cloudbrute"     "github.com/0xsha/CloudBrute@latest"



# ── Amass ──────────────────────────────────────────────────────
if ! command -v amass &> /dev/null; then
    echo -e "${CYAN}[*] Installing amass...${NC}"
    go install "github.com/owasp-amass/amass/v4/...@master" 2>/dev/null || \
    snap install amass 2>/dev/null || \
    echo -e "${RED}[-] Amass install failed — try: snap install amass${NC}"
fi

# ── RustScan ───────────────────────────────────────────────────
if ! command -v rustscan &> /dev/null; then
    echo -e "${CYAN}[*] Installing rustscan...${NC}"
    if command -v cargo &> /dev/null; then
        cargo install rustscan 2>/dev/null && echo -e "${GREEN}[+] rustscan installed${NC}"
    else
        # Download binary directly
        RUSTSCAN_URL="https://github.com/RustScan/RustScan/releases/latest/download/rustscan_amd64.deb"
        wget -q "$RUSTSCAN_URL" -O /tmp/rustscan.deb 2>/dev/null && \
            dpkg -i /tmp/rustscan.deb 2>/dev/null && \
            echo -e "${GREEN}[+] rustscan installed via deb${NC}" || \
            echo -e "${RED}[-] rustscan install failed${NC}"
    fi
fi

# ── Python Tools ───────────────────────────────────────────────
echo -e "${YELLOW}[*] Installing Python tools...${NC}"

# Create virtual environment
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate

pip install --upgrade pip -q
pip install -r requirements.txt -q && echo -e "${GREEN}[+] Python requirements installed${NC}"
# Explicitly ensure latest Gemini SDK
pip install google-genai -q 2>/dev/null && echo -e "${GREEN}[+] google-genai SDK installed${NC}"

# dnsgen
pip install dnsgen -q 2>/dev/null && echo -e "${GREEN}[+] dnsgen installed${NC}"

# ── Wordlists ──────────────────────────────────────────────────
echo -e "${YELLOW}[*] Setting up wordlists...${NC}"

# Check for SecLists
if [ ! -d "/usr/share/seclists" ]; then
    echo -e "${CYAN}[*] Installing SecLists (this may take a while)...${NC}"
    apt-get install -y -qq seclists 2>/dev/null || \
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null || \
    echo -e "${YELLOW}[!] SecLists not installed. Add wordlists manually to wordlists/ dir${NC}"
fi

# Create local wordlist dirs
mkdir -p wordlists/{subdomains,directories,parameters,api,cloud,permutations,resolvers}

# Copy key SecLists wordlists if available
if [ -d "/usr/share/seclists" ]; then
    cp /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
       wordlists/subdomains/subdomains.txt 2>/dev/null || true
    cp /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
       wordlists/directories/directories.txt 2>/dev/null || true
    cp /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
       wordlists/api/api_paths.txt 2>/dev/null || true
    echo -e "${GREEN}[+] SecLists wordlists copied${NC}"
fi

# ── .env setup ─────────────────────────────────────────────────
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo -e "${YELLOW}[!] Created .env file — add your API keys!${NC}"
fi

# ── Final Check ────────────────────────────────────────────────
echo ""
echo -e "${CYAN}┌─────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│           SETUP COMPLETE                 │${NC}"
echo -e "${CYAN}└─────────────────────────────────────────┘${NC}"
echo ""
echo -e "Next steps:"
echo -e "  1. ${YELLOW}source venv/bin/activate${NC}"
echo -e "  2. ${YELLOW}Edit .env and add your API keys${NC}"
echo -e "  3. ${YELLOW}python main.py --check-tools${NC}"
echo -e "  4. ${YELLOW}python main.py${NC}"
echo ""
