require('dotenv').config({
    path: "./.env"
});
const mongoose = require('mongoose');
const needle = require('needle');
const Chart = require('chart.js/auto');
const token = process.env.TWITTER_BEARER_TOKEN; //authentication. Use .env
const rulesURL = 'https://api.twitter.com/2/tweets/search/stream/rules';
const streamURL = 'https://api.twitter.com/2/tweets/search/stream';
const canvas = require("canvas");
const fs = require("fs");

//Note there seems to be problems with saving documents such as POC etc from twitter. Im not sure why this is, but ive omitted that from the data set 
//for documents added to the database. 


// Create a Mongoose schema for the tweets
const tweetSchema = new mongoose.Schema({
    id: String,
    text: String,
    created_at: Date,
    mentionsCve: Boolean,
    mentionsVulnerability: Boolean,
    mentionsExploit: Boolean,
    mentionsHack: Boolean,
    mentionsMalware: Boolean,
    mentionsPhishing: Boolean,
    mentionsInfosec: Boolean,
    mentionsPassword: Boolean,
    mentionsBreach: Boolean,
    mentionsThreat: Boolean,
    mentionsCybercrime: Boolean,
    mentionsCyberwarfare: Boolean,
    cve_mentioned: Array,
    cwe_mentioned: Array,
    nvd_link: String
});

// Create a Mongoose model for the tweets and counts
const Tweet = mongoose.model('Tweet', tweetSchema);
const countSchema = new mongoose.Schema({
    list: Array,
    Exists: Number
})
const counts = mongoose.model('TCounts', countSchema);
var Tc = 0; // this initiallizes the counts for the number of tweets mentioned per time frame (defined by the timeout function)
var maxHours = 24 * 60 * 6; //entry every 10 seconds, two iterations is a minute, 60 minutes in an hour, 24 hours per day
//rules used to initialize tweet live filtering.

const rules = [{
    value: '"cyber security" lang:en'
}, {
    value: '"data breach" lang:en'
}, {
    value: '"hackers" lang:en'
}, {
    value: '"network security" lang:en'
}, {
    value: '"phishing" lang:en'
}, {
    value: '"ransomware" lang:en'
}, {
    value: '"vulnerability" lang:en'
}, {
    value: '"zero day" lang:en'
}, {
    value: '"cyber attack" lang:en'
}, {
    value: '"cybercrime" lang:en'
}, {
    value: '"cybersecurity threat" lang:en'
}, {
    value: '"information security" lang:en'
}, {
    value: '"internet security" lang:en'
}, {
    value: '"malware" lang:en'
}, {
    value: '"security breach" lang:en'
}, ]; //rules are needed to act as filters for the live stream of twitter data.
async function getAllRules() { //fetches all rules from the search stream

    const response = await needle('get', rulesURL, {
        headers: {
            "authorization": `Bearer ${token}` //header is specific
        }
    })

    if (response.statusCode !== 200) {
        console.log("Error:", response.statusMessage, response.statusCode) //logs error
        throw new Error(response.body);
    }

    return (response.body);
}

async function deleteAllRules(rules) { //name self explanatory

    if (!Array.isArray(rules.data)) {
        return null;
    }

    const ids = rules.data.map(rule => rule.id);

    const data = {
        "delete": {
            "ids": ids
        }
    }

    const response = await needle('post', rulesURL, data, {
        headers: {
            "content-type": "application/json",
            "authorization": `Bearer ${token}` //must ensure header is correct.
        }
    })

    if (response.statusCode !== 200) {
        throw new Error(`Received non-200 status code: ${response.statusCode}. Response body: ${response.body}`);

    }

    return (response.body);

}

async function setRules() { //sets rules for the stream

    const data = {
        "add": rules //rules to add, defined above.
    }

    const response = await needle('post', rulesURL, data, {
        headers: {
            "content-type": "application/json",
            "authorization": `Bearer ${token}`
        }
    })

    if (response.statusCode !== 201) {
        throw new Error(response.body);
    }

    return (response.body);

}
// Connect to the MongoDB database
mongoose.connect(process.env.MONGOURL, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    })
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch((error) => {
        console.error(error);
    });

function streamConnect(retryAttempt) { //primary function. This is what handles the live feed from twitter. 

    const stream = needle.get(streamURL, { //uses needle to secure stream feed. 
        headers: {
            "User-Agent": "v2FilterStreamJS",
            "Authorization": `Bearer ${token}`
        },
        timeout: 20000
    });

    stream.on('data', async data => { //if something mathches our rules, lets start analyzing it. 
        try {

            //check to see if tweet contains words generally associated with cybersec. Ideally this would be done by AI and be probability based, not boolean based. 
            //I started training of a neural net model to handle this, but its so far not useful. Training should be made easier with the below categorization of tweets
            // as of writing this the database has over 1000 documents but it has been erased several times in efforts to improve training data (by making filters more aggressive)

            const json = JSON.parse(data);
            console.log(json);
            var Vuln = false;
            var Exploit = false;
            var Hack = false;
            var Malware = false;
            var Phishing = false;
            var Infosec = false
            var Password = false;
            var Breach = false;
            var Threat = false;
            var Cybercrime = false;
            var Cyberwarfare = false;
            const expWords = /exploit|utilisation|exposed/i;
            const hackWords = /hack|group|organization|credentials|stolen|ransomware/i;
            const malwareWords = /ransomware|ransom|stolen|authentication|bot|crypto|theif|steal|trojan|worm|virus|rat|remote|execution|priv/i;
            const phishingWords = /phishing|fishing|scam|fraud|phreaking/i;
            const infosecWords = /account|profile|name|dox|address|ip|token|print/i;
            const passwordWords = /account|profile|credentials|password|username|email|gmail|user|name|leak/i;
            const breachWords = /credentials|access|leak|corp|breach/i;
            const threatWords = /theft|steal|ransom|payment|delete|encrypt|conceil|threat/i;
            const cybercrimeWords = /theft|money|funds|passwords|account|credentials|login|leak|ddos|rce|crime/i;
            const cyberwarfareWords = /terror|ddos|war/i;
            if (json.data.text.match(/CVE-\d{4}-\d{4,}/gi) !== null || json.data.text.includes("vuln") || json.data.text.includes("vulnerability")) {
                Vulncheck = true;
            }
            //assign booleans
            Exploit = expWords.test(json.data.text);
            Hack = hackWords.test(json.data.text);
            Malware = malwareWords.test(json.data.text);
            Phishing = phishingWords.test(json.data.text);
            Infosec = infosecWords.test(json.data.text);
            Password = passwordWords.test(json.data.text);
            Breach = breachWords.test(json.data.text);
            Threat = threatWords.test(json.data.text);
            Cybercrime = cybercrimeWords.test(json.data.text);
            Cyberwarfare = cyberwarfareWords.test(json.data.text);

            //define documents data to be pushed to db.
            const tweetData = {
                id: json.data.id,
                text: json.data.text,
                created_at: new Date(),
                mentionsCve: ((json.data.text.match(/CVE-\d{4}-\d{4,}/gi) !== null)),
                mentionsVulnerability: ((json.data.text.match(/CVE-\d{4}-\d{4,}/gi) !== null)),
                mentionsExploit: Exploit,
                mentionsHack: Hack,
                mentionsMalware: Malware,
                mentionsPhishing: Phishing,
                mentionsInfosec: Infosec,
                mentionsPassword: Password,
                mentionsBreach: Breach,
                mentionsThreat: Threat,
                mentionsCybercrime: Cybercrime,
                mentionsCyberwarfare: Cyberwarfare,
                cve_mentioned: (json.data.text.match(/CVE-\d{4}-\d{4,}/gi) || []),
                cwe_mentioned: (json.data.text.match(/CWE-\d{1,}/gi) || []),
                nvd_link: (json.data.entities && json.data.entities.urls.length > 0) ? json.data.entities.urls[0].expanded_url : '',
            };
            console.log(tweetData)
            // Save tweet data to MongoDB
            // Sometimes the filter will pick up unrelated tweets that do not appear relevant to cybersecurity. If the tweet is relevant, we will save it and update
            // the tweet count. otherwise, theres no point and the tweet will be ignored. This will not affect the generated graph. 
            if (Exploit || Hack || Malware || Infosec || Password || Breach || Threat || Cybercrime || Cyberwarfare) {
                console.log("At least one of the variables is true");
                Tc += 1; //increments the count
                const tw = new Tweet(tweetData); //saves data to database. 
                tw.save().then(() => console.log('added'))
                    .catch(function(error) {
                        console.log('ERROR: ' + error);
                    });
            } else {
                console.log("None of the variables are true");
            }

            // A successful connection resets retry count.
            retryAttempt = 0;
        } catch (e) {
            if (data.detail === "This stream is currently at the maximum allowed connection limit.") {
                //this error is thrown sometimes, probably due to race conditions. I think I've completely fixed it
                //but its worth mentioning.
                console.log(data.detail)
                process.exit(1)
                //this error is critical, so we will cut things short if its thrown.
            } else {
                // Keep alive signal received. Do nothing.
            }
        }
    }).on('err', error => {
        if (error.code !== 'ECONNRESET') {
            console.log(error.code);
            process.exit(1);
            //cant recover from this error reasonably. 
        } else {
            setTimeout(() => {
                console.warn("A connection error occurred. Reconnecting...")
                streamConnect(++retryAttempt);
            }, 2 ** retryAttempt)
        }
    });

    return stream;

}
(async () => {
    let currentRules;

    try {
        // Rules are basically your filter. With no rules you can get unfiltered data. this is overwhelming sometimes in terms of quantity
        // But can be useful when experimenting with what keywords are important, and which are not. For example, sometimes CVE alone will 
        // Return more documents without cves than with. Thats because of slang terms for other thigns unrelated to cybersec. 
        // Gets the complete list of rules currently applied to the stream
        currentRules = await getAllRules();

        // Delete all rules. Comment the line below if you want to keep your existing rules.
        await deleteAllRules(currentRules);

        // Add rules to the stream. Comment the line below if you don't want to add new rules.
        await setRules();

    } catch (e) {
        console.error(e);
        process.exit(1);
    }
    async function myFunc() {
        //fairly self explanatory, just updates the count document. uses common mongo $ flags. 
        counts.findOneAndUpdate({
                Exists: 1
            }, {
                $push: {
                    list: Tc
                },
                $cond: {
                    if: {
                        $gte: [{
                            $size: "$list"
                        }, maxHours]
                    },
                    then: {
                        $slice: ["$list", -maxHours]
                    },
                    else: "$list"
                }
            }, {
                new: true,
                upsert: true
            },
            (err, res) => {
                if (err) {
                    console.log(err);
                } else {
                    if (res.list.length < maxHours) {
                        res.list.push(Tc);
                    } else {
                        //Tc = 0;
                        res.list = [0]; // resets the list to 0 if there are more entries than are possible in 24 hours. 

                    }
                    Tc = 0;
                    res.save().catch(err => console.log(err));
                    genGraph(res.list)
                }
            }
        );

        setTimeout(myFunc, 10000); //every 10s
    }

    function genGraph(res) {
        //generates data. this can be complicated as ive tinkered with the variables to get the best possible results.
        //The variables are wrong and misleading. ignore them, or change them. 

        const chartData = {
            labels: [],
            datasets: [],
        };
        const canvasNode = canvas.createCanvas(800, 500);
        const ctx = canvasNode.getContext("2d");

        // 6 entries  
        const maxSixEntries = 6; // represents 1m as every scan is done in 10 s
        const maxSixtyEntries = 30; // represents 5 minutes (5*6)
        const maxThreeThousandSixHundredEntries = 360; // represents 1 hour (6*60)
        const maxTwentyFourHoursEntries = 8640; // represents 24 hours (6*60*24)
        const colors = ["red", "blue", "green", "purple"]; // chart colors, these are defined within the module im using to generate charts. 
        // It also accepts rgb. 
        const sixEntries = res.slice(-maxSixEntries); //we only want the first minute of data for the first line

        const sixEntriesData = {
            label: "1 minute",
            data: sixEntries,
            backgroundColor: colors[0],
            borderColor: colors[0],
            fill: false,
        };
        chartData.datasets.push(sixEntriesData); //adds the data to a conglomerate of data.

        // 60 entries
        const sixtyEntries = res.slice(-maxSixtyEntries); // only want the first 5 minutes. its not 60 entries, its 30
        const sixtyEntriesData = {
            label: "10 minutes",
            data: sixtyEntries,
            backgroundColor: colors[1],
            borderColor: colors[1],
            fill: false,
        };
        chartData.datasets.push(sixtyEntriesData); //data to data

        // 3600 entries
        const threeThousandSixHundredEntries = res.slice(-maxThreeThousandSixHundredEntries); //its not actually 3600 but an order of magnitude less
        const threeThousandSixHundredEntriesData = {
            label: "1 hour",
            data: threeThousandSixHundredEntries,
            backgroundColor: colors[2],
            borderColor: colors[2],
            fill: false,
        };
        chartData.datasets.push(threeThousandSixHundredEntriesData); //data to data

        // All entries
        const allEntriesData = { //the res.list is reset every 24 hours as a result of the maxHours variable. this is done in myFunc
            label: "24 hours",
            data: res,
            backgroundColor: colors[3],
            borderColor: colors[3],
            fill: false,
        };
        chartData.datasets.push(allEntriesData);

        // Determine the maximum TC count to set the y-axis scale
        let maxTc = 0;
        res.forEach((count) => {
            if (count > maxTc) {
                maxTc = count;
            }
        });
        const yScaleMax = maxTc + (0.1 * maxTc); // Add 10% padding to y-axis scale

        // Set chart options with dynamic y-axis scale
        const myChart = new Chart(ctx, {
            type: "line",
            data: chartData,
            options: {
                scales: {
                    xAxes: [{
                        scaleLabel: {
                            display: true,
                            labelString: "Time",
                        },
                    }, ],
                    yAxes: [{
                        ticks: {
                            max: yScaleMax,
                        },
                        scaleLabel: {
                            display: true,
                            labelString: "TC count",
                        },
                    }, ],
                },
            },
        });

        // Draw lines for each dataset
        chartData.datasets.forEach((dataset) => {
            ctx.strokeStyle = dataset.borderColor;
            ctx.beginPath();
            dataset.data.forEach((count, i) => {
                const x = (i / (dataset.data.length - 1)) * (canvasNode.width - 80) + 50;
                const y = (1 - count / yScaleMax) * (canvasNode.height - 60) + 30;
                if (i === 0) {
                    ctx.moveTo(x, y);
                } else {
                    ctx.lineTo(x, y);
                }
            });
            ctx.stroke();
        });
        //outputs the data to a file. 
        const buffer = canvasNode.toBuffer("image/jpeg");
        fs.writeFile("tc_chart.jpg", buffer, function(err) {
            if (err) throw err;
            console.log("Chart saved to tc_chart.jpg");
        });
    }
    setTimeout(myFunc, 10000); //I prefer settimeout rather than direct execution as it is non-blocking.
    streamConnect(0);
})();