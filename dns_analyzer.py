import csv
import requests
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import time

def get_dns_info(domain):
    url = f"https://nslookup.techweirdo.net/api/lookup?domain={domain}"
    while True:
        response = requests.get(url)
        print(f"NSLookup API Status Code for {domain}: {response.status_code}")  # Log the HTTP status code
        if response.status_code == 200:
            dns_data = response.json()
            print(f"NSLookup API Response for {domain}: {dns_data}")  # Log the raw response
            if not dns_data:  # Check if the response is empty
                print(f"NSLookup API empty response received for {domain}")
            return dns_data, response.status_code
        elif response.status_code in [503, 500]:  # Ajout du code 500
            print(f"NSLookup API Service Unavailable for {domain}. Retrying in 10 seconds...")
            time.sleep(10)  # Wait for 10 seconds before retrying
        else:
            print(f"NSLookup API Error fetching data for {domain}: {response.status_code}")  # Log the error code
            return None, response.status_code

def get_whois_info(domain, api_key):
    url = f"https://api.apilayer.com/whois/query?domain={domain}"
    headers = {
        "apikey": api_key
    }
    retries = 0
    wait_times = [0, 10, 10, 20]  # 1ère tentative, 1er retry, 2e retry
    while retries < 3:
        if wait_times[retries] > 0:
            print(f"WhoIs API: Waiting {wait_times[retries]}s before retry {retries} for {domain}")
            time.sleep(wait_times[retries])
        try:
            response = requests.get(url, headers=headers)
            print(f"WhoIs API response for {domain}: {response.status_code} - {response.text}")  # Ajout du log
            if response.status_code == 200:
                return response.json(), response.status_code
            else:
                print(f"Error fetching WhoIs API data for {domain}: {response.status_code}")
        except Exception as e:
            print(f"Exception while fetching WhoIs API data for {domain}: {str(e)}")
        retries += 1
    # Dernière tentative après 20s si toujours pas 200
    print(f"WhoIs API: Waiting 20s before last attempt for {domain}")
    time.sleep(20)
    try:
        response = requests.get(url, headers=headers)
        print(f"WhoIs API response for {domain}: {response.status_code} - {response.text}")
        if response.status_code == 200:
            return response.json(), response.status_code
        else:
            print(f"Error fetching WhoIs API data for {domain}: {response.status_code}")
            return None, response.status_code
    except Exception as e:
        print(f"Exception while fetching WhoIs API data for {domain}: {str(e)}")
        return None, None

def format_dns_data(dns_data):
    if not dns_data:
        return {}
        
    formatted_data = {}
    
    # Traitement des enregistrements A (limité à 2)
    a_values = dns_data.get('A', [])
    formatted_data['A_1'] = a_values[0] if len(a_values) > 0 else ''
    formatted_data['A_2'] = a_values[1] if len(a_values) > 1 else ''
    
    # Traitement des enregistrements NS (limité à 5)
    ns_values = dns_data.get('NS', [])
    for i in range(1, 6):
        formatted_data[f'NS_{i}'] = ns_values[i-1] if i <= len(ns_values) else ''
    
    # Traitement des enregistrements CNAME (limité à 5)
    cname_values = dns_data.get('CNAME', [])
    for i in range(1, 6):
        formatted_data[f'CNAME_{i}'] = cname_values[i-1] if i <= len(cname_values) else ''
    
    # Traitement des enregistrements AAAA (limité à 5)
    aaaa_values = dns_data.get('AAAA', [])
    for i in range(1, 6):
        formatted_data[f'AAAA_{i}'] = aaaa_values[i-1] if i <= len(aaaa_values) else ''
    
    # Traitement des enregistrements TXT (limité à 5)
    txt_values = dns_data.get('TXT', [])
    for i in range(1, 6):
        formatted_data[f'TXT_{i}'] = txt_values[i-1] if i <= len(txt_values) else ''
    
    # Traitement des enregistrements MX (limité à 5)
    mx_values = dns_data.get('MX', [])
    for i in range(1, 6):
        formatted_data[f'MX_{i}'] = mx_values[i-1] if i <= len(mx_values) else ''
    
    return formatted_data

def format_whois_data(whois_data):
    print("Debug : whois_data reçu:", whois_data)  # Ajoute ce log
    if not whois_data or 'result' not in whois_data:
        return {}
    result = whois_data['result']
    return {
        'registrar': result.get('registrar', ''),
        'creation_date': result.get('creation_date', ''),
        'expiration_date': result.get('expiration_date', ''),
        'registrant_name': result.get('registrant', {}).get('name', '') if 'registrant' in result else '',
        'registrant_email': result.get('registrant', {}).get('email', '') if 'registrant' in result else ''
    }

def find_next_filename(base_name):
    counter = 0
    while os.path.exists(f"{base_name}_{counter}.csv"):
        counter += 1
    return f"{base_name}_{counter}.csv"

def process_csv(input_csv, log_widget, api_key=None):
    output_file = "dns_output.csv"
    empty_responses = 0  # Counter for empty API responses

    # Define fieldnames for output
    fieldnames = ['id', 'asset', 'nslookup_status_code', 'whois_status_code'] + \
                 [f'A_{i}' for i in range(1, 3)] + \
                 [f'NS_{i}' for i in range(1, 6)] + \
                 [f'CNAME_{i}' for i in range(1, 6)] + \
                 [f'AAAA_{i}' for i in range(1, 6)] + \
                 [f'TXT_{i}' for i in range(1, 6)] + \
                 [f'MX_{i}' for i in range(1, 6)]

    # Add WHOIS fields if API key is provided
    if api_key:
        fieldnames.extend(['registrar', 'creation_date', 'expiration_date', 'registrant_name', 'registrant_email'])

    csvfile = open(input_csv, newline='', encoding='utf-8-sig')
    reader = csv.DictReader(csvfile, delimiter=';')
    if 'id' not in reader.fieldnames or 'asset' not in reader.fieldnames:
        log_widget.insert(tk.END, "The 'id' and 'asset' columns must be present in the input CSV file.\n")
        return

    total_assets = sum(1 for _ in reader)
    csvfile.seek(0)  # Reset reader to the start of the file
    next(reader)  # Skip header

    def process_next(index=1):
        nonlocal empty_responses
        try:
            row = next(reader)
        except StopIteration:
            print("================ ANALYSIS COMPLETED ================")
            messagebox.showinfo("Success", "Analysis completed.")
            csvfile.close()
            return

        domain = row.get('asset')
        print("\n================ Domain's DNS analysis in progress ==================")
        print(f"Starting domain processing: {domain} (line {index}/{total_assets})")
        if domain is None:
            log_widget.insert(tk.END, f"Warning: 'asset' column not found for line {index}\n")
        else:
            log_widget.insert(tk.END, f"Processing {index}/{total_assets}: {domain}\n")
            log_widget.see(tk.END)

            print("-- NSLookup API call --")
            dns_info, nslookup_status_code = get_dns_info(domain)
            if not dns_info:
                empty_responses += 1
                percentage_empty = (empty_responses / index) * 100
                log_widget.insert(tk.END, f"NSLookup API empty response for {domain}. Empty responses percentage: {percentage_empty:.2f}%\n")
            formatted_dns_info = format_dns_data(dns_info) if dns_info else {}

            whois_status_code = ''
            if api_key:
                print("-- WhoIs API call --")
                whois_info, whois_status_code = get_whois_info(domain, api_key)
                formatted_whois_info = format_whois_data(whois_info) if whois_info else {}
                formatted_dns_info.update(formatted_whois_info)

            print("-- Wrinting into the CSV --")
            row_to_write = {'id': row.get('id', ''), 'asset': domain, 'nslookup_status_code': nslookup_status_code, 'whois_status_code': whois_status_code, **formatted_dns_info}
            print("Debug : line written in the CSV:", row_to_write)  # Log before writing
            with open(output_file, 'a', newline='') as outfile:
                writer = csv.DictWriter(outfile, fieldnames=fieldnames)
                if index == 1:  # Write header only once
                    writer.writeheader()
                writer.writerow(row_to_write)

            print(f"DNS analysis completed for {domain}")
            print("===================================================\n")

            log_widget.insert(tk.END, f"CSV updated for {domain}\n")
            log_widget.see(tk.END)

        # Schedule the next iteration after 5000 milliseconds (5 seconds)
        log_widget.after(5000, process_next, index + 1)

    process_next()

def open_file_dialog(log_widget):
    file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if file_path:
        with open(file_path, newline='', encoding='utf-8-sig') as csvfile:
            reader = csv.reader(csvfile, delimiter=';')
            lines = list(reader)
            log_widget.insert(tk.END, f"File loaded: {file_path}\n")
            log_widget.insert(tk.END, f"Total number of lines: {len(lines) - 1}\n")
            log_widget.insert(tk.END, "First lines:\n")
            for line in lines[:5]:
                log_widget.insert(tk.END, f"{line}\n")
            log_widget.see(tk.END)
        return file_path
    return None

def main():
    root = tk.Tk()
    root.title("DNS Analyzer")

    log_widget = scrolledtext.ScrolledText(root, width=80, height=20)
    log_widget.pack(padx=10, pady=10)

    file_path = None
    api_key = None

    def load_file():
        nonlocal file_path
        file_path = open_file_dialog(log_widget)

    def start_processing():
        if file_path:
            process_csv(file_path, log_widget, api_key)
        else:
            messagebox.showwarning("Warning", "Please first load a CSV file.")

    # Add WHOIS API key input
    api_key_frame = tk.Frame(root)
    api_key_frame.pack(pady=5)
    
    api_key_label = tk.Label(api_key_frame, text="WhoIs API key (optional):")
    api_key_label.pack(side=tk.LEFT, padx=5)
    
    api_key_entry = tk.Entry(api_key_frame, width=40)
    api_key_entry.pack(side=tk.LEFT, padx=5)
    
    def update_api_key():
        nonlocal api_key
        api_key = api_key_entry.get() if api_key_entry.get() else None
        if api_key:
            log_widget.insert(tk.END, "WhoIs API key configured.\n")
        else:
            log_widget.insert(tk.END, "No WhoIs API key configured.\n")
        log_widget.see(tk.END)

    button_frame = tk.Frame(root)
    button_frame.pack(pady=5)

    load_button = tk.Button(button_frame, text="Load a CSV", command=load_file)
    load_button.pack(side=tk.LEFT, padx=5)

    process_button = tk.Button(button_frame, text="Start processing", command=start_processing)
    process_button.pack(side=tk.LEFT, padx=5)

    # Add button to update API key
    update_key_button = tk.Button(api_key_frame, text="Update API key", command=update_api_key)
    update_key_button.pack(side=tk.LEFT, padx=5)

    root.mainloop()

if __name__ == "__main__":
    main()
