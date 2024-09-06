const { exec } = require("child_process");
const fs = require('fs');

/**
 * This function leverages the is-my-node-vulnerable package
 * (https://github.com/RafaelGSS/is-my-node-vulnerable/blob/main/index.js) and
 * extends it to be able to suppress / expire suppressions for pipeline use.
 */
function scanNode(){
    exec('npx is-my-node-vulnerable', (error, stdout, stderr) => {
        
        // is-my-node-vulnerable module treats vulnerable node scans as errors,
        // therefore we have to parse this output and come to our own conclusion
        // whether to pass/fail based on ignored vulnerabilities (if any).
        if (stderr) {

            // Ignore file with specified CVes to ignore from vulnerability check
            const ignoreFile = './nodescan.json'
            const json = JSON.parse(fs.readFileSync(ignoreFile)).vulnerabilities;

            // Get every CVE vulnerability blurb along with patched versions from is-my-node-vulnerable output
            pattern = /CVE-\d*-\d*.+?Patched versions.+?\n/gs
            var output = stderr.match(pattern);

            validVulns = [];

            output.forEach((line,index) => {
                // Gether CVE code from vulnerabiltiy blurb
                const reportedCve = line.match(/^CVE-\d{4}-\d{4,}/g);
                
                if(pattern.test(line)){
                    // Check for a match between ignored vunlneabilites and one found in is-my-node-vulnerable
                    const vulnerability = json.find(({cve}) => cve == reportedCve);
                    
                    if(!vulnerability){
                        // If vulnerability is not being ignored in ignore file, treat it as a valid vulnerability.
                        validVulns.push(line);
                    }else{
                        // If vulnerability is being ignores, ensure the exiry date is valid.
                        const expiryDate = Date.parse(vulnerability.expiry);
                        if(expiryDate && (expiryDate > new Date())){
                            validVulns.push(line);
                        }else{
                            console.log(`Ignoring vulnerability ${reportedCve} \n`)
                        }
                    }
                    
                }
            })

            // Output valid vulnerabilities and trigger proper exit code.
            if(validVulns){
                console.log('Your version of Node has the following vulnerabilities to investigate....... \n');
                //Output all valid vulnerabilities
                validVulns.forEach(vuln => {
                console.log(vuln);
                })
                process.exit(1);
            } else { process.exitCode(0)} 
            
            return;
        }
    
        // If execution succeeds, the node version is not vulnerable and no work needs to be done.
        console.log(`${stdout}`);
        process.exit(0);


    });
}

module.exports = scanNode

