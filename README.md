# Unknown Proxies IP Abuse Checker

This project uses the AbuseIPDB API and checks proxies from the `ipsToCheck.txt` file. 

The `ipsToCheck.txt` file should have 1 proxy per line.

The script will output the response from AbuseIPDB in a CSV format.

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create a `.env` file in the root directory with your AbuseIPDB API key:
   ```
   ABUSEIPDB_API_KEY=your_api_key_here
   ```

3. Add IP addresses to check in `ipsToCheck.txt` (one IP per line).

## Usage

Run the script:
```bash
npm start
```

or

```bash
node check.js
```

The script will:
- Validate all IP addresses in `ipsToCheck.txt`
- Check each valid IP against AbuseIPDB API
- Output results in CSV format to the console