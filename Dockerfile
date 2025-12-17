# 1. Use official Python slim image as base
FROM python:3.10-slim

# Set working directory
WORKDIR /app

RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    git \
    curl \
    nmap \
    wfuzz \
    sqlmap \
    p7zip-full \
    ca-certificates \
    python3-pip \
    python3-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    hashcat \
    python3-setuptools \
    dnsutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 3. Set up tools directory
RUN mkdir -p /tools
ENV PATH="/tools:${PATH}"

# 4. Install Go-based tools from pre-compiled amd64 binaries
RUN cd /tmp && \
    wget -q --tries=3 --timeout=30 https://github.com/projectdiscovery/nuclei/releases/download/v3.4.10/nuclei_3.4.10_linux_amd64.zip && \
    unzip -q -o nuclei_3.4.10_linux_amd64.zip && mv nuclei /tools/ && \
    rm -f nuclei_3.4.10_linux_amd64.zip

RUN cd /tmp && \
    wget -q --tries=3 --timeout=30 https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz && \
    tar -xzf ffuf_2.1.0_linux_amd64.tar.gz && mv ffuf /tools/ && \
    rm -f ffuf_2.1.0_linux_amd64.tar.gz

RUN cd /tmp && \
    wget -q --tries=3 --timeout=30 https://github.com/projectdiscovery/httpx/releases/download/v1.6.3/httpx_1.6.3_linux_amd64.zip && \
    unzip -q -o httpx_1.6.3_linux_amd64.zip && mv httpx /tools/ && \
    rm -f httpx_1.6.3_linux_amd64.zip

RUN cd /tmp && \
    wget -q --tries=3 --timeout=30 https://github.com/projectdiscovery/subfinder/releases/download/v2.9.0/subfinder_2.9.0_linux_amd64.zip && \
    unzip -q -o subfinder_2.9.0_linux_amd64.zip && mv subfinder /tools/ && \
    rm -f subfinder_2.9.0_linux_amd64.zip

RUN cd /tmp && \
    wget -q --tries=3 --timeout=30 https://github.com/projectdiscovery/tlsx/releases/download/v1.2.1/tlsx_1.2.1_linux_amd64.zip && \
    unzip -q -o tlsx_1.2.1_linux_amd64.zip && mv tlsx /tools/ && \
    rm -f tlsx_1.2.1_linux_amd64.zip

RUN cd /tmp && \
    wget -q --tries=3 --timeout=30 https://github.com/jaeles-project/gospider/releases/download/v1.1.6/gospider_v1.1.6_linux_x86_64.zip && \
    unzip -q -o gospider_v1.1.6_linux_x86_64.zip && mv gospider_v1.1.6_linux_x86_64/gospider /tools/ && \
    rm -f gospider_v1.1.6_linux_x86_64.zip

RUN cd /tmp && \
    wget -q --tries=3 --timeout=30 https://github.com/owasp-amass/amass/releases/download/v5.0.0/amass_linux_amd64.tar.gz && \
    tar -xzf amass_linux_amd64.tar.gz && mv amass_linux_amd64/amass /tools/ && \
    rm -f amass_linux_amd64.tar.gz

# 5. Install Python-based tools
RUN git clone https://github.com/s0md3v/XSStrike.git /opt/XSStrike \
    && pip install -r /opt/XSStrike/requirements.txt || true

RUN git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch \
    && pip install -r /opt/dirsearch/requirements.txt || true



# 6. Install common.txt wordlist and set up dirsearch
RUN mkdir -p /usr/share/wordlists/dirb \
    && wget -O /usr/share/wordlists/dirb/common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    && echo -e "admin\nlogin\napi\nimages\nbackup" > /usr/share/wordlists/dirb/sample.txt \
    && ln -s /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch \
    && chmod +x /usr/local/bin/dirsearch

# 7. Set up hashcat
RUN mkdir -p /tools/hashcat && \
    ln -s /usr/bin/hashcat /tools/hashcat/hashcat.bin

# 8. Install Arjun
RUN pip install arjun

RUN pip install --no-cache-dir xsstrike \
    arjun \
    requests \
    beautifulsoup4 \
    lxml \
    python-nmap \
    paramiko \
    cryptography

# 9. Copy requirements.txt 
COPY requirements.txt .

# 10. Install Python dependencies 
RUN pip install --no-cache-dir -r requirements.txt

# 11. Copy project files 
COPY . .

# Start the MCP server with full logging and fallback
CMD ["python", "main.py"]

# Expose port 8081 for external access
EXPOSE 8081
ENV PORT=8081