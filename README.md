# DNS Analyzer

DNS Analyzer is an application that allows you to analyze DNS records for multiple domains from a CSV file. The application retrieves DNS information (A, NS, CNAME, AAAA, TXT, MX) as well as Whois data for each domain and generates a detailed report.

## Features

- Graphical user interface
- Analysis of DNS records (A, NS, CNAME, AAAA, TXT, MX for the first 5 entries)
- Support for input CSV files
- Generation of detailed reports
- Real-time progress tracking (logs in the terminal and in the application's log window)
- Display of empty response statistics

## Requirements

- Windows 10/11 or macOS 10.15+
- The application is standalone and does not require Python. Python is only needed if you want to modify or extend the solution.

## Installation

### Windows

1. Download the `DNS_Analyzer.exe` file
2. Double-click the file to launch the application

### macOS

1. Download the `DNS_Analyzer.app` file
2. Right-click the application and select "Open"
3. Confirm the opening in the security window

## Usage

1. Launch the application
2. Click "Load a CSV" to select your CSV file
   - The CSV file must contain at least two columns: 'id' and 'asset'
   - The separator must be a semicolon (;)
3. Click "Start processing" to begin the analysis
4. The report will be generated in the `dns_output.csv` file in the same folder as the application

## Input CSV File Format

The CSV file should have the following structure:
```csv
id;asset
1;example.com
2;example.org
```

## Output CSV File Format

The output file will contain the following columns:
- id: domain identifier
- asset: domain name
- whois: registrar
- A_1, A_2: A records (IPv4 addresses)
- NS_1 to NS_5: name servers
- CNAME_1 to CNAME_5: CNAME records
- AAAA_1 to AAAA_5: AAAA records (IPv6 addresses)
- TXT_1 to TXT_5: TXT records
- MX_1 to MX_5: mail servers

## Important Notes

- The application makes requests to a public DNS API (DNSLookup API available here : [https://nslookup.techweirdo.net/api/lookup?domain=google.fr](https://nslookup.techweirdo.net/api/lookup?domain=example.fr))
- To obtain Whois data, an API key (and thus an account) is required; as of now, the API is free for up to 3000 queries per month (here
  there is the page to create the credentials and the get the documentation : [https://apilayer.com/marketplace/whois-api](https://apilayer.com/marketplace/whois-api)
- Some TLD are not supported by the Whois API 
- A delay of 5 seconds is observed between each request to avoid overloading the API
- Empty responses are counted and their percentage is displayed in real time
- In case of an API error, the application automatically retries after 10 seconds until a response is received

## Support

For any questions or issues, please contact me at tommy.guyennot@okuden.fr.

## License

This project is licensed under the MIT License. 
