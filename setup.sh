#!/bin/bash
# Automated Setup Script for Secure Chat System

set -e  # Exit on error

echo "============================================"
echo "Secure Chat System - Automated Setup"
echo "============================================"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Python 3 is installed
echo -e "${YELLOW}[1/8]${NC} Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
fi
PYTHON_VERSION=$(python3 --version)
echo -e "${GREEN}✓ Found $PYTHON_VERSION${NC}"
echo ""

# Check if MySQL is installed
echo -e "${YELLOW}[2/8]${NC} Checking MySQL installation..."
if ! command -v mysql &> /dev/null; then
    echo -e "${RED}Error: MySQL is not installed${NC}"
    echo "Install with: sudo apt-get install mysql-server"
    exit 1
fi
MYSQL_VERSION=$(mysql --version)
echo -e "${GREEN}✓ Found $MYSQL_VERSION${NC}"
echo ""

# Install Python dependencies
echo -e "${YELLOW}[3/8]${NC} Installing Python dependencies..."
pip install cryptography>=41.0.0 PyMySQL>=1.1.0 python-dotenv>=1.0.0
echo -e "${GREEN}✓ Dependencies installed${NC}"
echo ""

# Setup environment file
echo -e "${YELLOW}[4/8]${NC} Setting up environment configuration..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${GREEN}✓ Created .env file${NC}"
    echo -e "${YELLOW}⚠ Please edit .env and set your MySQL password${NC}"
    echo "Run: nano .env"
    read -p "Press Enter after editing .env file..."
else
    echo -e "${GREEN}✓ .env file already exists${NC}"
fi
echo ""

# Create directories
echo -e "${YELLOW}[5/8]${NC} Creating project directories..."
mkdir -p certs
echo -e "${GREEN}✓ Directories created${NC}"
echo ""

# Generate certificates
echo -e "${YELLOW}[6/8]${NC} Generating certificates..."
if [ ! -f certs/ca_cert.pem ]; then
    python3 gen_ca.py
    echo -e "${GREEN}✓ Root CA generated${NC}"
else
    echo -e "${YELLOW}⚠ CA certificate already exists, skipping...${NC}"
fi

if [ ! -f certs/server_cert.pem ]; then
    python3 gen_cert.py localhost server
    echo -e "${GREEN}✓ Server certificate generated${NC}"
else
    echo -e "${YELLOW}⚠ Server certificate already exists, skipping...${NC}"
fi

if [ ! -f certs/client_cert.pem ]; then
    python3 gen_cert.py client1 client
    echo -e "${GREEN}✓ Client certificate generated${NC}"
else
    echo -e "${YELLOW}⚠ Client certificate already exists, skipping...${NC}"
fi
echo ""

# Setup database
echo -e "${YELLOW}[7/8]${NC} Setting up MySQL database..."
python3 setup_db.py
echo -e "${GREEN}✓ Database setup complete${NC}"
echo ""

# Verify setup
echo -e "${YELLOW}[8/8]${NC} Verifying setup..."
ERRORS=0

if [ ! -f certs/ca_cert.pem ]; then
    echo -e "${RED}✗ CA certificate missing${NC}"
    ERRORS=$((ERRORS + 1))
fi

if [ ! -f certs/server_cert.pem ]; then
    echo -e "${RED}✗ Server certificate missing${NC}"
    ERRORS=$((ERRORS + 1))
fi

if [ ! -f certs/client_cert.pem ]; then
    echo -e "${RED}✗ Client certificate missing${NC}"
    ERRORS=$((ERRORS + 1))
fi

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
else
    echo -e "${RED}✗ Setup incomplete: $ERRORS error(s) found${NC}"
    exit 1
fi
echo ""

# Display summary
echo "============================================"
echo -e "${GREEN}Setup Complete!${NC}"
echo "============================================"
echo ""
echo "To start the application:"
echo ""
echo "  Terminal 1 (Server):"
echo "    python3 server.py"
echo ""
echo "  Terminal 2 (Client):"
echo "    python3 client.py"
echo ""
echo "To verify certificates:"
echo "    openssl x509 -in certs/server_cert.pem -text -noout"
echo ""
echo "For more information, see README.md"
echo ""
