# Node-Scanner
Node Version Vulnerability Scanner lightweight CLI tool

This CLI tool is used in conjunction with [`is-my-node-vulnerable`](https://github.com/RafaelGSS/is-my-node-vulnerable), and allows you to properly identify and ignore vulnerabilities found in your installed Node version.

## How to run this tool

After installation, this tool can be run as follows:

`npx --yes @vertigis/node-scanner`

### Ignoring vulnerabilities

Vulnerabilities can be ignored by creating a file called `nodescan.json` at the root of your source directory. The json file is structured as follows:

```
{
    "vulnerabilities": [
        {    
            "cve": CVE is that is to be ignored,
            "expiry": Date in YYYY-MM-DD format,
            "statement": This is an optional property that allows for a comment on the vulnerability.
        },
        ...
    ]
}

```
