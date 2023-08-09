# Use the latest LTS version of Node.js as the base image
FROM node:lts

# Set the working directory in the container
WORKDIR /app

# Run the tool installation command
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.42.1

# Clone the code repository
RUN git clone https://github.com/ninh-nd/scanner-template.git .

ADD . ./

RUN npm install

# Replace content in index.js
RUN sed -i 's@<code_placeholder>@async function processImageScan(name) {  const cmd = `trivy image docker.io/${name} --scanners vuln --format json --quiet`;  const command = spawnSync(cmd, { shell: true });  const data = command.stdout.toString();  const validJson = replaceUnicodeEscapeSequences(data);  try {    const json = JSON.parse(validJson);    let response = [];    json.Results.forEach((res) => {      const vulnList = res.Vulnerabilities;      const processed = vulnList?.map((x) => {        const cveId = x?.VulnerabilityID;        const severity = x?.Severity;        const description = x?.Description;        const score = x?.CVSS?.nvd?.V3Score;        const cwes = x?.CweIDs;        return { cveId, severity, description, score, cwes };      });      response.push(processed);    });    response = response.flat();    await axios.post(`https://client-dashboard.up.railway.app/webhook/image`, {      eventCode: `IMAGE_SCAN_COMPLETE`,      imageName: name,      data: response,    });  } catch (err) {    fastify.log.error(err);  }}@' index.js

# Install Prettier to format the code
RUN npm install -g prettier

# Format the code
RUN prettier --write .

EXPOSE 3000

# Start the server when the container is run
CMD [ "npm", "start" ]
