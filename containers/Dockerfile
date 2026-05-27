ARG KALI_BASE_IMAGE=kalilinux/kali-rolling:2025.2
FROM ${KALI_BASE_IMAGE}

LABEL description="AI Agent Penetration Testing Environment with Comprehensive Automated Tools"

RUN apt-get update && \
    apt-get install -y kali-archive-keyring sudo && \
    apt-get update

RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    touch /home/pentester/.hushlogin

RUN mkdir -p /home/pentester/tools /app/certs && \
    chown -R pentester:pentester /app/certs /home/pentester/tools

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget curl git vim nano unzip tar \
    apt-transport-https ca-certificates gnupg lsb-release \
    build-essential software-properties-common \
    gcc libc6-dev pkg-config libpcap-dev libssl-dev \
    python3 python3-pip python3-dev python3-venv python3-setuptools \
    golang-go \
    net-tools dnsutils whois \
    jq parallel ripgrep grep \
    less man-db procps htop \
    iproute2 iputils-ping netcat-traditional \
    nmap ncat ndiff \
    sqlmap nuclei subfinder naabu ffuf \
    nodejs npm pipx \
    libcap2-bin \
    gdb \
    libnss3-tools \
    chromium fonts-liberation


RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

USER pentester
RUN openssl ecparam -name prime256v1 -genkey -noout -out /app/certs/ca.key && \
    openssl req -x509 -new -key /app/certs/ca.key \
    -out /app/certs/ca.crt \
    -days 3650 \
    -subj "/C=US/ST=CA/O=Security Testing/CN=Testing Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" && \
    openssl pkcs12 -export \
    -out /app/certs/ca.p12 \
    -inkey /app/certs/ca.key \
    -in /app/certs/ca.crt \
    -passout pass:"" \
    -name "Testing Root CA" && \
    chmod 644 /app/certs/ca.crt && \
    chmod 600 /app/certs/ca.key && \
    chmod 600 /app/certs/ca.p12

USER root
RUN cp /app/certs/ca.crt /usr/local/share/ca-certificates/ca.crt && \
    update-ca-certificates

ARG UV_VERSION=0.11.16
RUN python3 -m pip install --no-cache-dir "uv==${UV_VERSION}"

USER pentester
WORKDIR /tmp

ARG HTTPX_VERSION=v1.9.0
ARG KATANA_VERSION=v1.6.1
ARG CVEMAP_VERSION=v2.0.1
ARG GOSPIDER_VERSION=v1.1.6
ARG INTERACTSH_VERSION=v1.3.1
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION} && \
    go install -v github.com/projectdiscovery/cvemap/cmd/vulnx@${CVEMAP_VERSION} && \
    go install -v github.com/jaeles-project/gospider@${GOSPIDER_VERSION} && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@${INTERACTSH_VERSION}

RUN nuclei -update-templates

ARG ARJUN_VERSION=2.2.7
ARG DIRSEARCH_VERSION=0.4.3.post1
ARG WAFW00F_VERSION=2.4.2
RUN pipx install "arjun==${ARJUN_VERSION}" && \
    pipx install "dirsearch==${DIRSEARCH_VERSION}" && \
    pipx inject dirsearch 'setuptools<81' && \
    pipx install "wafw00f==${WAFW00F_VERSION}"

ENV NPM_CONFIG_PREFIX=/home/pentester/.npm-global
RUN mkdir -p /home/pentester/.npm-global

ARG RETIRE_VERSION=5.4.3
ARG ESLINT_VERSION=10.4.0
ARG JS_BEAUTIFY_VERSION=1.15.4
ARG AST_GREP_VERSION=0.43.0
ARG TREE_SITTER_CLI_VERSION=0.26.0
ARG AGENT_BROWSER_VERSION=0.27.0
RUN npm install -g "retire@${RETIRE_VERSION}" && \
    npm install -g "eslint@${ESLINT_VERSION}" && \
    npm install -g "js-beautify@${JS_BEAUTIFY_VERSION}" && \
    npm install -g "@ast-grep/cli@${AST_GREP_VERSION}" && \
    npm install -g "tree-sitter-cli@${TREE_SITTER_CLI_VERSION}" && \
    npm install -g "agent-browser@${AGENT_BROWSER_VERSION}"

ENV AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium
ENV AGENT_BROWSER_USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
ENV AGENT_BROWSER_ARGS="--disable-blink-features=AutomationControlled,--no-first-run,--no-default-browser-check,--lang=en-US"
ENV AGENT_BROWSER_SCREENSHOT_DIR=/workspace/.agent-browser-screenshots
RUN /home/pentester/.npm-global/bin/agent-browser doctor --offline --quick

ARG TREE_SITTER_JAVA_COMMIT=e10607b45ff745f5f876bfa3e94fbcc6b44bdc11
ARG TREE_SITTER_JAVASCRIPT_COMMIT=58404d8cf191d69f2674a8fd507bd5776f46cb11
ARG TREE_SITTER_PYTHON_COMMIT=26855eabccb19c6abf499fbc5b8dc7cc9ab8bc64
ARG TREE_SITTER_GO_COMMIT=2346a3ab1bb3857b48b29d779a1ef9799a248cd7
ARG TREE_SITTER_BASH_COMMIT=a06c2e4415e9bc0346c6b86d401879ffb44058f7
ARG TREE_SITTER_JSON_COMMIT=001c28d7a29832b06b0e831ec77845553c89b56d
ARG TREE_SITTER_YAML_COMMIT=a1c4812a73ec5e089de8e441fdea3a921e8d5079
ARG TREE_SITTER_TYPESCRIPT_COMMIT=75b3874edb2dc714fb1fd77a32013d0f8699989f
RUN set -eux; \
    clone_pinned() { \
        repo_url="$1"; \
        dest="$2"; \
        commit="$3"; \
        if [ ! -d "$dest" ]; then \
            git clone "$repo_url" "$dest"; \
            git -C "$dest" checkout --detach "$commit"; \
        fi; \
    }; \
    TS_PARSER_DIR="/home/pentester/.tree-sitter/parsers"; \
    mkdir -p "${TS_PARSER_DIR}"; \
    clone_pinned "https://github.com/tree-sitter/tree-sitter-java.git" "${TS_PARSER_DIR}/tree-sitter-java" "${TREE_SITTER_JAVA_COMMIT}"; \
    clone_pinned "https://github.com/tree-sitter/tree-sitter-javascript.git" "${TS_PARSER_DIR}/tree-sitter-javascript" "${TREE_SITTER_JAVASCRIPT_COMMIT}"; \
    clone_pinned "https://github.com/tree-sitter/tree-sitter-python.git" "${TS_PARSER_DIR}/tree-sitter-python" "${TREE_SITTER_PYTHON_COMMIT}"; \
    clone_pinned "https://github.com/tree-sitter/tree-sitter-go.git" "${TS_PARSER_DIR}/tree-sitter-go" "${TREE_SITTER_GO_COMMIT}"; \
    clone_pinned "https://github.com/tree-sitter/tree-sitter-bash.git" "${TS_PARSER_DIR}/tree-sitter-bash" "${TREE_SITTER_BASH_COMMIT}"; \
    clone_pinned "https://github.com/tree-sitter/tree-sitter-json.git" "${TS_PARSER_DIR}/tree-sitter-json" "${TREE_SITTER_JSON_COMMIT}"; \
    clone_pinned "https://github.com/tree-sitter-grammars/tree-sitter-yaml.git" "${TS_PARSER_DIR}/tree-sitter-yaml" "${TREE_SITTER_YAML_COMMIT}"; \
    clone_pinned "https://github.com/tree-sitter/tree-sitter-typescript.git" "${TS_PARSER_DIR}/tree-sitter-typescript" "${TREE_SITTER_TYPESCRIPT_COMMIT}"; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" "${TS_PARSER_DIR}/tree-sitter-typescript-typescript"; \
    fi; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" "${TS_PARSER_DIR}/tree-sitter-typescript-tsx"; \
    fi; \
    tree-sitter init-config >/dev/null 2>&1 || true; \
    TS_CONFIG="/home/pentester/.config/tree-sitter/config.json"; \
    mkdir -p "$(dirname "${TS_CONFIG}")"; \
    [ -f "${TS_CONFIG}" ] || printf '{}\n' > "${TS_CONFIG}"; \
    TMP_CFG="$(mktemp)"; \
    jq --arg p "${TS_PARSER_DIR}" '.["parser-directories"] = ((.["parser-directories"] // []) + [$p] | unique)' "${TS_CONFIG}" > "${TMP_CFG}"; \
    mv "${TMP_CFG}" "${TS_CONFIG}"

WORKDIR /home/pentester/tools
ARG JS_SNOOPER_COMMIT=932704cbce1a04ebe89a558f395a6e474e01b15b
ARG JSNIPER_COMMIT=65d0b508dc88e6de3dfe6ac60e6d89eca22be686
ARG JWT_TOOL_COMMIT=3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b
RUN git clone https://github.com/aravind0x7/JS-Snooper.git && \
    git -C JS-Snooper checkout --detach "${JS_SNOOPER_COMMIT}" && \
    chmod +x JS-Snooper/js_snooper.sh && \
    git clone https://github.com/xchopath/jsniper.sh.git && \
    git -C jsniper.sh checkout --detach "${JSNIPER_COMMIT}" && \
    chmod +x jsniper.sh/jsniper.sh && \
    git clone https://github.com/ticarpi/jwt_tool.git && \
    git -C jwt_tool checkout --detach "${JWT_TOOL_COMMIT}" && \
    chmod +x jwt_tool/jwt_tool.py

USER root

ARG TRUFFLEHOG_VERSION=v3.95.3
ARG GITLEAKS_VERSION=v8.30.1
ARG TRIVY_VERSION=v0.70.0
RUN GOBIN=/usr/local/bin go install -v github.com/trufflesecurity/trufflehog/v3@${TRUFFLEHOG_VERSION} && \
    GOBIN=/usr/local/bin go install -v github.com/gitleaks/gitleaks/v8@${GITLEAKS_VERSION} && \
    GOBIN=/usr/local/bin go install -v github.com/aquasecurity/trivy/cmd/trivy@${TRIVY_VERSION}

RUN apt-get update && apt-get install -y zaproxy

RUN apt-get install -y wapiti

USER pentester

ARG SEMGREP_VERSION=1.163.0
ARG BANDIT_VERSION=1.9.4
RUN pipx install "semgrep==${SEMGREP_VERSION}" && \
    pipx install "bandit==${BANDIT_VERSION}"

ARG JSHINT_VERSION=2.13.6
RUN npm install -g "jshint@${JSHINT_VERSION}"

USER root

RUN apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/.venv"

WORKDIR /app

ARG CAIDO_VERSION=0.56.0
ARG CAIDO_SHA256_X86_64=""
ARG CAIDO_SHA256_AARCH64=""
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        CAIDO_ARCH="x86_64"; \
        CAIDO_SHA256="${CAIDO_SHA256_X86_64}"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        CAIDO_ARCH="aarch64"; \
        CAIDO_SHA256="${CAIDO_SHA256_AARCH64}"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    wget -O caido-cli.tar.gz "https://caido.download/releases/v${CAIDO_VERSION}/caido-cli-v${CAIDO_VERSION}-linux-${CAIDO_ARCH}.tar.gz" && \
    if [ -n "$CAIDO_SHA256" ]; then \
        echo "${CAIDO_SHA256}  caido-cli.tar.gz" | sha256sum -c -; \
    else \
        echo "WARNING: CAIDO checksum build arg not set; skipping checksum verification"; \
    fi && \
    tar -xzf caido-cli.tar.gz && \
    chmod +x caido-cli && \
    rm caido-cli.tar.gz && \
    mv caido-cli /usr/local/bin/

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN mkdir -p /workspace && chown -R pentester:pentester /workspace /app

USER pentester
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/pip install --no-cache-dir caido-sdk-client && \
    /app/.venv/bin/pip install --no-cache-dir -r /home/pentester/tools/jwt_tool/requirements.txt && \
    printf '%s\n' \
        '#!/bin/bash' \
        'exec /app/.venv/bin/python /home/pentester/tools/jwt_tool/jwt_tool.py "$@"' \
        > /home/pentester/.local/bin/jwt_tool && \
    chmod +x /home/pentester/.local/bin/jwt_tool

COPY --chown=pentester:pentester strix/tools/proxy/caido_api.py /opt/strix-python/caido_api.py
ENV PYTHONPATH=/opt/strix-python

RUN echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:$PATH"' >> /home/pentester/.bashrc && \
    echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:$PATH"' >> /home/pentester/.profile

USER root
COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER pentester
WORKDIR /workspace

ENTRYPOINT ["docker-entrypoint.sh"]
