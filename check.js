require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
const path = require('path');

// Validate IP address format
function isValidIP(ip) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip.trim());
}

// Read IPs from file
function readIPsFromFile(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const lines = content.split('\n')
            .map(line => line.trim())
            .filter(line => line.length > 0);
        return lines;
    } catch (error) {
        console.error(`Error reading file ${filePath}:`, error.message);
        process.exit(1);
    }
}

// Parse CSV and extract IP addresses from the first column
function getExistingIPsFromCSV(csvFilePath) {
    const existingIPs = new Set();
    
    try {
        if (!fs.existsSync(csvFilePath)) {
            return existingIPs;
        }
        
        const content = fs.readFileSync(csvFilePath, 'utf-8').trim();
        if (content.length === 0) {
            return existingIPs;
        }
        
        const lines = content.split('\n');
        // Skip header row (first line)
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (line.length === 0) continue;
            
            // Parse CSV line - handle quoted values
            // Simple CSV parser: split by comma but respect quoted fields
            const fields = [];
            let currentField = '';
            let inQuotes = false;
            
            for (let j = 0; j < line.length; j++) {
                const char = line[j];
                
                if (char === '"') {
                    if (inQuotes && line[j + 1] === '"') {
                        // Escaped quote
                        currentField += '"';
                        j++; // Skip next quote
                    } else {
                        // Toggle quote state
                        inQuotes = !inQuotes;
                    }
                } else if (char === ',' && !inQuotes) {
                    // End of field
                    fields.push(currentField);
                    currentField = '';
                } else {
                    currentField += char;
                }
            }
            fields.push(currentField); // Add last field
            
            // First column is IP Address
            if (fields.length > 0) {
                const ip = fields[0].trim();
                // Only add if it's a valid IP format (not "ERROR" or empty)
                if (ip && ip !== 'ERROR' && isValidIP(ip)) {
                    existingIPs.add(ip);
                }
            }
        }
    } catch (error) {
        console.error(`Error reading CSV file ${csvFilePath}:`, error.message);
        // Don't exit, just return empty set - we'll still try to process IPs
    }
    
    return existingIPs;
}

// Check IP with AbuseIPDB API
async function checkIP(ipAddress, apiKey) {
    const url = 'https://api.abuseipdb.com/api/v2/check';
    
    try {
        const response = await axios.get(url, {
            params: {
                'ipAddress': ipAddress,
                'maxAgeInDays': '90'
            },
            headers: {
                'Accept': 'application/json',
                'Key': apiKey
            }
        });
        
        return {
            ip: ipAddress,
            success: true,
            data: response.data
        };
    } catch (error) {
        return {
            ip: ipAddress,
            success: false,
            error: error.response?.data || error.message
        };
    }
}

// Escape CSV values that contain commas or quotes
function escapeCSV(value) {
    if (value === null || value === undefined) {
        return '';
    }
    const stringValue = String(value);
    if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
        return `"${stringValue.replace(/"/g, '""')}"`;
    }
    return stringValue;
}

// Convert response to CSV row
function formatAsCSV(result) {
    if (!result.success) {
        return `${escapeCSV(result.ip)},ERROR,${escapeCSV(JSON.stringify(result.error))}`;
    }
    
    const data = result.data.data;
    return [
        escapeCSV(data.ipAddress || result.ip),
        escapeCSV(data.isPublic ?? ''),
        escapeCSV(data.ipVersion ?? ''),
        escapeCSV(data.isWhitelisted ?? false),
        escapeCSV(data.abuseConfidenceScore ?? 0),
        escapeCSV(data.countryCode || ''),
        escapeCSV(data.countryName || ''),
        escapeCSV(data.usageType || ''),
        escapeCSV(data.isp || ''),
        escapeCSV(data.domain || ''),
        escapeCSV(data.hostnames ? data.hostnames.join(';') : ''),
        escapeCSV(data.isTor ?? false),
        escapeCSV(data.totalReports ?? 0),
        escapeCSV(data.numDistinctUsers ?? 0),
        escapeCSV(data.lastReportedAt || '')
    ].join(',');
}

// Main function
async function main() {
    // Check for API key
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!apiKey || apiKey === 'YOUR_OWN_API_KEY') {
        console.error('Error: ABUSEIPDB_API_KEY environment variable is not set or is using the default value.');
        console.error('Please set your API key in a .env file. See .env.example for reference.');
        process.exit(1);
    }
    
    // Read IPs from file
    const ipsFile = path.join(__dirname, 'ipsToCheck.txt');
    const ipLines = readIPsFromFile(ipsFile);
    
    if (ipLines.length === 0) {
        console.error('Error: No IPs found in ipsToCheck.txt');
        process.exit(1);
    }
    
    // Validate IPs
    const validIPs = [];
    const invalidIPs = [];
    
    ipLines.forEach((ip, index) => {
        if (isValidIP(ip)) {
            validIPs.push(ip);
        } else {
            invalidIPs.push({ line: index + 1, ip });
        }
    });
    
    // Report invalid IPs
    if (invalidIPs.length > 0) {
        console.error('Invalid IP addresses found:');
        invalidIPs.forEach(({ line, ip }) => {
            console.error(`  Line ${line}: "${ip}"`);
        });
        process.exit(1);
    }
    
    console.log(`Found ${validIPs.length} valid IP address(es). Checking...`);
    
    // CSV Header
    const csvHeader = 'IP Address,Is Public,IP Version,Is Whitelisted,Abuse Confidence Score,Country Code,Country Name,Usage Type,ISP,Domain,Hostnames,Is Tor,Total Reports,Distinct Users,Last Reported At';
    const csvFile = path.join(__dirname, 'checkedIPs.csv');
    
    // Get existing IPs from CSV to avoid duplicate API calls
    const existingIPs = getExistingIPsFromCSV(csvFile);
    if (existingIPs.size > 0) {
        console.log(`Found ${existingIPs.size} IP(s) already in CSV. Skipping duplicates...`);
    }
    
    // Check if file exists and has content
    let fileExists = false;
    let hasHeader = false;
    try {
        if (fs.existsSync(csvFile)) {
            const existingContent = fs.readFileSync(csvFile, 'utf-8').trim();
            if (existingContent.length > 0) {
                fileExists = true;
                // Check if header exists (first line matches our header)
                const firstLine = existingContent.split('\n')[0];
                hasHeader = firstLine === csvHeader;
            }
        }
    } catch (error) {
        console.error(`Error reading existing CSV file:`, error.message);
        process.exit(1);
    }
    
    // Filter out IPs that already exist in CSV
    const ipsToCheck = validIPs.filter(ip => !existingIPs.has(ip));
    const skippedIPs = validIPs.filter(ip => existingIPs.has(ip));
    
    if (skippedIPs.length > 0) {
        console.log(`Skipping ${skippedIPs.length} IP(s) already in CSV: ${skippedIPs.join(', ')}`);
    }
    
    if (ipsToCheck.length === 0) {
        console.log('All IPs have already been checked. No new API calls needed.');
        return;
    }
    
    console.log(`Checking ${ipsToCheck.length} new IP(s)...`);
    
    // Collect CSV rows
    const csvRows = [];
    
    // Add header only if file doesn't exist or doesn't have header
    if (!fileExists || !hasHeader) {
        csvRows.push(csvHeader);
    }
    
    // Check each IP
    for (const ip of ipsToCheck) {
        console.log(`Checking ${ip}...`);
        const result = await checkIP(ip, apiKey);
        const csvRow = formatAsCSV(result);
        csvRows.push(csvRow);
        
        // Add a small delay to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    // Append CSV to file
    try {
        const contentToAppend = csvRows.join('\n') + '\n';
        fs.appendFileSync(csvFile, contentToAppend, 'utf-8');
        console.log(`\nResults appended to ${csvFile}`);
    } catch (error) {
        console.error(`Error writing CSV file:`, error.message);
        process.exit(1);
    }
}

// Run the script
main().catch(error => {
    console.error('Unexpected error:', error);
    process.exit(1);
});

