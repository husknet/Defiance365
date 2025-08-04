import axios from 'axios';
import geoip from 'geoip-lite';
import stringSimilarity from 'string-similarity';

const KNOWN_BOT_ISPS = [
  "RGT/SMP", "chinatelecom.cn", "petersburg internet network ltd.", "prospero ooo", "cdn77 lon", "bath", "netrouting b.v.",
  "vultr holdings llc frankfurt", "ionos cloud vl5.wdr.gb", "estnoc global", "abuseradar.com", "m247 europe toronto infrastructure",
  "freedomtech solutions limited", "virtualine technologies", "foundation for applied privacy", "sem soft",
  "chinanet jiangsu province network", "unknown", "quantumshift communications", "brightspeed", "fbw networks sas",
  "soloway wright llp", "oracle public cloud", "level 3 parent, llc", "ovh hosting, inc.", "vpn consumer london, united kingdom",
  "ro qns", "m247.ro", "contabo inc.", "digital energy technologies limited", "express equinix london",
  "american registry for internet numbers", "meta networks inc", "nortonlifelock canada corporation",
  "mimecast north america inc", "pulsar informatique inc.", "zap hosting.com", "national agency for network services",
  "gtd internet s.a.", "psinet, inc.", "telecom colocation, llc", "distributel communications limited", "cdn77 chi pop",
  "united legwear", "cleardocks llc", "centurylink communications, llc", "493networking.cc", "geofeed",
  "altushost luxembourg network", "greenfloid.com", "ophl", "egn dedicated servers asia optimized", "m247 ltd new york",
  "hornetsecurity gmbh", "onyphe sas", "play fbb", "packethub s.a.", "internet security cheapyhost", "ippn holdings ltd",
  "satelcom internet inc.", "iway ag", "truview llc", "david prado rodriguez", "palo alto networks, inc", "driftnet.io",
  "vultr holdings, llc", "virtuo networks france", "amazon data services nova", "censys,inc.", "lantek llc", "ovh us llc",
  "egihosting", "hwc cable", "claro nxt telecomunicacoes ltda", "internet archive", "6 collyer quay", "cyberaccesdata inc.",
  "leaseweb canada inc.", "xinet solutions sa de cv", "aventice llc", "city west cable & telephone corp.",
  "optimum online cablevision systems", "ftn tilepikoinonies mepe", "techoff srv limited", "cloudflarenet eu", "tzulo, inc.",
  "Cyber Assets FZCO", "Falco Networks B.V.", "PJSC Rostelecom", "Gtd Internet S.A.", "Meta Networks Inc", "PRIVATE LAYER INC",
  "Bucklog SARL", "FBW Reseaux Fibres inc.", "OpenVPN", "Huawei Cloud Hongkong Region", "Excitel Broadband Pvt Ltd",
  "VPN Consumer Frankfurt, Germany", "M Nets SAL", "HostRoyale Technologies Pvt Ltd", "The Constant Company, LLC", "bgm",
  "Microcom Informatique, Inc.", "Contabo Inc", "TELECABLE RESIDENCIAL", "Network for Tor-Exit traffic.", "LogicWeb Inc.",
  "Microsoft Corp", "google llc", "Microsoft Corporation", "Contabo Inc.", "c-lutions inc", "Barry Hamel Equipment Ltd",
  "DLF Cable Network", "Packethub S.A.", "DataCamp s.r.o.", "Bharti Airtel Limited", "Clouvider",
  "Facebook", "Internet Archive", "QuickPacket, LLC", "Amazon Data Services Singapore", "PJSC MTS Sverdlovsk region", "HOME_DSL",
  "Amazon Data Services NoVa", "M247 LTD Berlin Infrastructure", "BRETAGNE TELECOM SASU", "M247 Ltd - Brazil Infrastructure",
  "ZAP-Hosting.com - IF YOU WANT MORE POWER", "ZAP-Hosting GmbH", "Artic Solutions SARL", "UCLOUD", "Cox Communications Inc.",
  "ONYPHE SAS", "Internet Utilities Europe and Asia Limited", "KYOCERA AVX Components (Dresden) GmbH", "Blix Group AS",
  "Kaopu Cloud HK Limited", "Cyber Assets FZCO", "Total server solutions LLC", "Internet Utilities Africa (PTY) LTD",
  "Atria Convergence Technologies Ltd.,", "Linode", "Bayer AG, Germany, Leverkusen", "TeraGo Networks Inc.", "Microsoft Corporation",
  "Zscaler, Inc.", "BT global Communications India Private Limited-Access", "Not SURF Net", "Nothing to hide",
  "TOTAL PLAY TELECOMUNICACIONES SA DE CV", "Driftnet Ltd", "Telstra Limited", "OVH US LLC", "TT DOTCOM SDN BHD", "OVH (NWK)",
  "Zayo Bandwidth", "Accenture LLP", "Kyivstar GSM", "Cascades", "Microsoft Limited", "Netcraft", "Rockion LLC",
  "Sudhana Telecommunications Private Limited", "COMPASS COMPRESSION SERVICES LTD", "DigitalOcean", "Amazon Technologies Inc.",
  "Google LLC", "Datacamp Limited", "Helsinki, Finland", "NorthernTel Limited Partnership", "China Unicom Shandong province network",
  "CHINA UNICOM Shanghai city network", "China Unicom Henan province network", "KDDI CORPORATION", "Reliance Jio Infocomm Limited",
  "Linode, LLC", "OVH SAS", "OVH Hosting, Inc.", "Hetzner Online GmbH", "Alibaba", "Oracle Corporation", "SoftLayer Technologies",
  "Fastly", "Cloudflare", "Cloudflare London, LLC", "Akamai Technologies", "Akamai Technologies Inc.", "Hurricane Electric",
  "Hostwinds", "Choopa", "Contabo GmbH", "Leaseweb", "Censys, Inc.", "Windscribe", "Hatching International B.V.", "Asm Technologies",
  "Leaseweb Deutschland GmbH", "Amazon.com, Inc.", "Amazon Data Services Ireland Limited", "Scaleway", "Vultr",
  "apnic research and development", "private customer", "Ubiquity", "liteserver"
];

const WHITELISTED_ISPS = [
  "shaw communications",
  "bell canada",
  "rogers communications",
  "telus",
  "verizon",
  "at&t",
  "comcast",
  "spectrum",
  "cox communications",
  "bt group",
  "sky uk"
];

const KNOWN_BOT_ASNS = ['AS16509', 'AS14061', 'AS13335', 'AS8075', 'AS212238'];

const TRAFFIC_THRESHOLD = 10;
const TRAFFIC_TIMEFRAME = 30 * 1000;
const TRAFFIC_DATA = {};
const ISP_SIMILARITY_THRESHOLD = 0.7;
// Utilities

function fuzzyMatchISP(isp) {
  if (WHITELISTED_ISPS.includes(isp.toLowerCase())) return false;
  const match = stringSimilarity.findBestMatch(isp.toLowerCase(), KNOWN_BOT_ISPS);
  return match.bestMatch.rating > ISP_SIMILARITY_THRESHOLD;
}

async function checkIPReputation(ip) {
  try {
    const res = await axios.get("https://api.abuseipdb.com/api/v2/check", {
      headers: {
        Key: process.env.ABUSEIPDB_API_KEY,
        Accept: 'application/json'
      },
      params: { ipAddress: ip, maxAgeInDays: 30 },
      timeout: 4000
    });
    return res.data.data.abuseConfidenceScore >= 50;
  } catch (error) {
    console.error("❌ AbuseIPDB check failed:", error.message);
    return false;
  }
}

export default async function handler(req, res) {
  try {
    res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGINS || '*');
    res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, POST');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    // ✅ Static API Key Authentication
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || apiKey !== process.env.API_KEY) {
      console.warn("🔒 Invalid API key");
      return res.status(401).json({ error: 'Unauthorized: Invalid API key.' });
    }

    // ✅ Origin check
    const origin = req.headers.origin || '';
    const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',');
    if (process.env.ALLOWED_ORIGINS !== '*' && !allowedOrigins.includes(origin)) {
      console.warn("🚫 Forbidden origin:", origin);
      return res.status(403).json({ error: 'Forbidden: Origin not allowed.' });
    }

    const { user_agent, ip } = req.body;
    if (!ip || !user_agent) {
      return res.status(400).json({ error: 'Missing required fields.' });
    }

    const isBotUserAgent = [/bot/, /crawl/, /scraper/, /spider/, /httpclient/, /python/]
      .some(p => p.test(user_agent.toLowerCase()));

    const isIPAbuser = await checkIPReputation(ip);

    let isp = 'unknown', asn = 'unknown', country = 'unknown';
    try {
      const geoRes = await axios.get("https://api.ipgeolocation.io/ipgeo", {
        params: {
          apiKey: process.env.IPGEOLOCATION_API_KEY,
          ip
        },
        timeout: 4000
      });

      isp = geoRes.data?.isp?.toLowerCase() || 'unknown';
      asn = geoRes.data?.asn || 'unknown';
      country = geoRes.data?.country_name || 'unknown';
    } catch (err) {
      const geoData = geoip.lookup(ip);
      country = geoData?.country || 'unknown';
    }

    const isScraperISP = fuzzyMatchISP(isp);
    const isDataCenterASN = KNOWN_BOT_ASNS.includes(asn);

    const now = Date.now();
    if (!TRAFFIC_DATA[ip]) TRAFFIC_DATA[ip] = [];
    TRAFFIC_DATA[ip] = TRAFFIC_DATA[ip].filter(ts => now - ts < TRAFFIC_TIMEFRAME);
    TRAFFIC_DATA[ip].push(now);
    const isSuspiciousTraffic = TRAFFIC_DATA[ip].length > TRAFFIC_THRESHOLD;

    const riskFactors = [
      isBotUserAgent,
      isScraperISP,
      isIPAbuser,
      isDataCenterASN,
      isSuspiciousTraffic
    ];

    const score = riskFactors.filter(Boolean).length / riskFactors.length;
    const isBot = score >= 0.5;

    return res.status(200).json({
      is_bot: isBot,
      score,
      country,
      details: {
        isp,
        asn,
        user_agent,
        isBotUserAgent,
        isScraperISP,
        isIPAbuser,
        isSuspiciousTraffic,
        isDataCenterASN
      }
    });

  } catch (err) {
    console.error("🔥 Internal Server Error:", err.message || err.stack);
    return res.status(500).json({ error: "Internal server error" });
  }
}
