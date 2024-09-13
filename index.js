const { exec } = require("child_process");
const fs = require("fs");
/**
 * This function leverages the is-my-node-vulnerable package
 * (https://github.com/RafaelGSS/is-my-node-vulnerable/blob/main/index.js) and
 * extends it to be able to suppress / expire suppressions for pipeline use.
 */
function scanNode() {
  exec("npx is-my-node-vulnerable@^1", (error, stdout, stderr) => {
    /* is-my-node-vulnerable module treats vulnerable node scans as errors,
     * therefore we have to parse this output and come to our own conclusion
     * whether to pass/fail based on ignored vulnerabilities (if any).

     * A sample output of is-my-node-vulnerable can be found in text file
     * sample_vulnerable_output.txt at the root of this package.
    */
    if (stderr) {
      // Get every CVE vulnerability blurb along with patched versions
      // from is-my-node-vulnerable output
      pattern = /CVE-\d{4}-\d{4,}.+?Patched versions.+?\n/gs;
      var output = stderr.match(pattern);

      validVulns = [];

      const ignoreFile = "./nodescan.json";
      if (
        fs.existsSync(ignoreFile) &&
        JSON.parse(fs.readFileSync(ignoreFile)).vulnerabilities
      ) {
        // Ignore file with specified CVes to ignore from vulnerability
        // check
        const json = JSON.parse(fs.readFileSync(ignoreFile)).vulnerabilities;
        output.forEach((line, index) => {
          // Gether CVE code from vulnerabiltiy blurb
          const reportedCve = line.match(/^CVE-\d{4}-\d{4,}/g);

          if (line.match(pattern)) {
            // Check for a match between ignored vunlneabilites and
            // one found in is-my-node-vulnerable
            const vulnerability = json.find(({ cve }) => cve == reportedCve);
            if (!vulnerability) {
              // If vulnerability is not being ignored in ignore
              // file, treat it as a valid vulnerability.
              validVulns.push(line);
            } else {
              // If vulnerability is being ignores, ensure the
              // expiry date is valid.
              const expiryDate = Date.parse(vulnerability.expiry);
              if (expiryDate > Date.now()) {
                validVulns.push(line);
              } else {
                console.log(`Ignoring vulnerability ${reportedCve} \n`);
              }
            }
          }
        });
      } else {
        console.log("No ignore file found, no vulnerabilities to be ignored.");

        output.forEach((line) => {
          validVulns.push(line);
        });
      }

      // Output valid vulnerabilities and trigger proper exit code.
      if (validVulns) {
        console.log(
          "Your version of Node has the following vulnerabilities to investigate....... \n"
        );
        //Output all valid vulnerabilities
        validVulns.forEach((vuln) => {
          console.log(vuln);
        });
        process.exit(1);
      } else {
        process.exitCode(0);
      }

      return;
    }

    // If execution succeeds, the node version is not vulnerable and no work
    // needs to be done.
    console.log(`${stdout}`);
    process.exit(0);
  });
}

module.exports = scanNode;
