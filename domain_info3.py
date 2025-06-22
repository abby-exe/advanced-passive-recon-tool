import whois
import dns.resolver
import requests
from fpdf import FPDF
import socket
import ssl
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os
import re
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import socket
import urllib.parse
from googlesearch import search
import exiftool
import tempfile

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 14)
        self.cell(0, 10, 'Advanced Domain Information Report', 0, 1, 'C')
        self.ln(10)

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 8, title, 0, 1, 'L')
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 6, body)
        self.ln(2)

    def add_section(self, title, body):
        self.add_page()
        self.chapter_title(title)
        self.chapter_body(body)

    def add_key_value_pair(self, key, value):
        self.set_font('Arial', 'B', 10)
        self.cell(0, 6, f"{key}:", ln=True)
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 6, str(value))
        self.ln(2)

    def add_list(self, title, items):
        self.set_font('Arial', 'B', 10)
        self.cell(0, 6, f"{title}:", ln=True)
        self.set_font('Arial', '', 10)
        for item in items:
            self.multi_cell(0, 6, f" - {item}")
        self.ln(2)

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        parsed_data = {
            "Domain Name": w.domain_name,
            "Registrar": w.registrar,
            "Creation Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Last Updated": w.updated_date,
            "Name Servers": w.name_servers,
            "Registrant": w.registrant,
            "Admin": w.admin,
            "Tech": w.tech,
            "Billing": w.billing,
            "Registrant Organization": w.org,
            "Registrant Country": w.country,
            "Registrant State/Province": w.state,
            "Registrant City": w.city,
            "Registrant Street": w.address,
            "Registrant Postal Code": w.zipcode,
            "Registrant Phone": w.phone,
            "Registrant Email": w.email,
            "Admin Organization": getattr(w, 'admin_org', 'N/A'),
            "Admin Country": getattr(w, 'admin_country', 'N/A'),
            "Admin State/Province": getattr(w, 'admin_state', 'N/A'),
            "Admin City": getattr(w, 'admin_city', 'N/A'),
            "Admin Street": getattr(w, 'admin_street', 'N/A'),
            "Admin Postal Code": getattr(w, 'admin_postalcode', 'N/A'),
            "Admin Phone": getattr(w, 'admin_phone', 'N/A'),
            "Admin Email": getattr(w, 'admin_email', 'N/A'),
            "Tech Organization": getattr(w, 'tech_org', 'N/A'),
            "Tech Country": getattr(w, 'tech_country', 'N/A'),
            "Tech State/Province": getattr(w, 'tech_state', 'N/A'),
            "Tech City": getattr(w, 'tech_city', 'N/A'),
            "Tech Street": getattr(w, 'tech_street', 'N/A'),
            "Tech Postal Code": getattr(w, 'tech_postalcode', 'N/A'),
            "Tech Phone": getattr(w, 'tech_phone', 'N/A'),
            "Tech Email": getattr(w, 'tech_email', 'N/A'),
            "DNSSEC": getattr(w, 'dnssec', 'N/A'),
            "Status": w.status
        }
        # Remove any None values
        parsed_data = {k: v for k, v in parsed_data.items() if v is not None}
        return parsed_data
    except Exception as e:
        return [("WHOIS Lookup failed", str(e))]

def parse_whois_output(whois_data):
    parsed = {}
    for key, value in whois_data.items():
        if isinstance(value, list):
            parsed[key] = ', '.join(map(str, value))
        else:
            parsed[key] = str(value)
    return parsed

def get_dns_info(domain):
    try:
        dns_info = []
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR']
        resolver = dns.resolver.Resolver()
        
        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                records = [str(rdata) for rdata in answers]
                if records:
                    dns_info.append((f"{record_type} Records", ', '.join(records)))
                else:
                    dns_info.append((f"{record_type} Records", "No records found"))
            except dns.resolver.NoAnswer:
                dns_info.append((f"{record_type} Records", "No records found"))
            except dns.resolver.NXDOMAIN:
                dns_info.append((f"{record_type} Records", "Domain does not exist"))
            except dns.exception.DNSException as e:
                dns_info.append((f"{record_type} Records", f"Lookup failed: {str(e)}"))
        
        return dns_info
    except Exception as e:
        return [("DNS Lookup failed", str(e))]

def get_nslookup_info(domain):
    try:
        nslookup_info = []
        a_records = dns.resolver.resolve(domain, 'A')
        for ip in a_records:
            result = subprocess.run(["nslookup", str(ip)], capture_output=True, text=True)
            nslookup_info.append((f"NSLookup Result for {ip}", result.stdout))
        return nslookup_info
    except Exception as e:
        return [("NSLookup failed", str(e))]

def get_subdomains(domain):
    try:
        subdomains = set()
        
        # Method 1: crt.sh
        response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json")
        if response.status_code == 200:
            for entry in response.json():
                subdomains.update(entry['name_value'].split('\n'))
        
        # Method 2: DNS bruteforce (simple implementation)
        common_subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange', 'ipv4']
        
        for subdomain in common_subdomains:
            try:
                socket.gethostbyname(f"{subdomain}.{domain}")
                subdomains.add(f"{subdomain}.{domain}")
            except socket.gaierror:
                pass
        
        return [("Subdomains", '\n'.join(sorted(subdomains)))]
    except Exception as e:
        return [("Subdomain Enumeration failed", str(e))]

def get_http_headers(domain):
    try:
        headers = {}
        for protocol in ['http', 'https']:
            try:
                response = requests.head(f"{protocol}://{domain}", timeout=5)
                headers[protocol] = [(key, value) for key, value in response.headers.items()]
            except requests.RequestException:
                headers[protocol] = [("Error", f"Failed to retrieve {protocol.upper()} headers")]
        return [("HTTP Headers", headers['http']), ("HTTPS Headers", headers['https'])]
    except Exception as e:
        return [("HTTP Headers retrieval failed", str(e))]

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_info = [
                    ("Issuer", ', '.join([f"{key}={value}" for key, value in cert['issuer'][0]])),
                    ("Subject", ', '.join([f"{key}={value}" for key, value in cert['subject'][0]])),
                    ("Version", cert['version']),
                    ("Serial Number", cert['serialNumber']),
                    ("Not Before", cert['notBefore']),
                    ("Not After", cert['notAfter']),
                    ("Subject Alternative Names", ', '.join([f"{name[0]}={name[1]}" for name in cert['subjectAltName']]))
                ]
        return ssl_info
    except Exception as e:
        return [("SSL Information retrieval failed", str(e))]

def get_social_media_links(domain):
    social_platforms = {
        "LinkedIn": f"https://www.linkedin.com/company/{domain}",
        "Facebook": f"https://www.facebook.com/{domain}",
        "Twitter": f"https://twitter.com/{domain}",
        "Instagram": f"https://www.instagram.com/{domain}",
        "YouTube": f"https://www.youtube.com/user/{domain}",
        "Pinterest": f"https://www.pinterest.com/{domain}",
        "GitHub": f"https://github.com/{domain}"
    }
    
    social_media_info = []
    for platform, url in social_platforms.items():
        try:
            response = requests.head(url, allow_redirects=True, timeout=5)
            if response.status_code == 200:
                social_media_info.append((platform, url))
        except requests.RequestException:
            pass
    
    if not social_media_info:
        social_media_info.append(("Note", "No confirmed social media profiles found"))
    social_media_info.append(("Disclaimer", "These links are based on common username patterns and may not be accurate"))
    return social_media_info

def get_web_technologies(domain):
    try:
        response = requests.get(f"http://{domain}", headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(response.text, 'html.parser')
        
        technologies = []
        
        # Check for common web technologies
        if soup.find(attrs={"name": "generator", "content": re.compile("WordPress", re.I)}):
            technologies.append("WordPress")
        if soup.find(attrs={"name": "generator", "content": re.compile("Joomla", re.I)}):
            technologies.append("Joomla")
        if soup.find(attrs={"name": "generator", "content": re.compile("Drupal", re.I)}):
            technologies.append("Drupal")
        if 'jquery' in response.text.lower():
            technologies.append("jQuery")
        if 'bootstrap' in response.text.lower():
            technologies.append("Bootstrap")
        if 'react' in response.text.lower():
            technologies.append("React")
        if 'angular' in response.text.lower():
            technologies.append("Angular")
        if 'vue' in response.text.lower():
            technologies.append("Vue.js")
        if 'php' in response.text.lower():
            technologies.append("PHP")
        if 'asp.net' in response.text.lower():
            technologies.append("ASP.NET")
        if 'laravel' in response.text.lower():
            technologies.append("Laravel")
        if 'django' in response.text.lower():
            technologies.append("Django")
        if 'ruby on rails' in response.text.lower():
            technologies.append("Ruby on Rails")
        
        server = response.headers.get('Server', '')
        if server:
            technologies.append(f"Server: {server}")
        
        return [("Web Technologies", ', '.join(technologies) if technologies else "No common technologies detected")]
    except Exception as e:
        return [("Web Technologies detection failed", str(e))]

def get_google_dorks(domain):
    dorks = [
        f"site:{domain} filetype:pdf",
        f"site:{domain} inurl:login",
        f"site:{domain} intitle:index.of",
        f"site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini",
        f"site:{domain} intext:password",
        f"site:{domain} intext:username",
        f"site:{domain} filetype:doc | filetype:docx | filetype:xls | filetype:xlsx | filetype:ppt | filetype:pptx",
        f"site:{domain} inurl:admin | inurl:login | inurl:wp-admin",
        f"site:{domain} intext:confidential | intext:proprietary",
        f"site:{domain} inurl:backup | inurl:old | inurl:archive"
    ]
    results = []
    for dork in dorks:
        encoded_dork = requests.utils.quote(dork)
        results.append((dork, f"https://www.google.com/search?q={encoded_dork}"))
    return results

def get_email_addresses(domain):
    try:
        email_addresses = set()
        
        # Method 1: Scrape website content
        response = requests.get(f"http://{domain}")
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, response.text)
        email_addresses.update(emails)
        
        # Method 2: Check common email formats
        common_usernames = ['info', 'contact', 'support', 'admin', 'sales', 'marketing', 'webmaster']
        for username in common_usernames:
            email = f"{username}@{domain}"
            try:
                socket.gethostbyname(email)
                email_addresses.add(email)
            except socket.gaierror:
                pass
        
        # Method 3: Search for email addresses in WHOIS data
        whois_info = get_whois_info(domain)
        if isinstance(whois_info, dict):
            for value in whois_info.values():
                if isinstance(value, str):
                    emails = re.findall(email_pattern, value)
                    email_addresses.update(emails)
        
        return list(email_addresses) if email_addresses else ["No email addresses found"]
    except Exception as e:
        return [f"Email harvesting failed: {str(e)}"]

def get_metadata(domain):
    try:
        response = requests.get(f"http://{domain}")
        soup = BeautifulSoup(response.text, 'html.parser')
        metadata = {}
        for meta in soup.find_all('meta'):
            key = meta.get('name') or meta.get('property')
            if key:
                metadata[key] = meta.get('content')
        return metadata
    except Exception as e:
        return {"Error": f"Metadata extraction failed: {str(e)}"}

def extract_metadata(url):
    try:
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
            
            result = subprocess.run(["exiftool", temp_file.name], capture_output=True, text=True)
            metadata = result.stdout
            
            os.unlink(temp_file.name)
            return metadata
        else:
            return {"Error": f"Failed to download file: HTTP {response.status_code}"}
    except Exception as e:
        return {"Error": f"File metadata extraction failed: {str(e)}"}

def get_certificate_transparency(domain):
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            for entry in data:
                name_value = entry.get('name_value', '')
                if name_value:
                    subdomains.add(name_value)
            return list(subdomains)
        else:
            return [f"Certificate transparency lookup failed: HTTP {response.status_code}"]
    except Exception as e:
        return [f"Certificate transparency lookup failed: {str(e)}"]

def get_public_repositories(domain):
    try:
        results = []
        
        # GitHub search
        github_url = f"https://github.com/search?q={domain}&type=repositories"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        github_response = requests.get(github_url, headers=headers)
        if github_response.status_code == 200:
            github_soup = BeautifulSoup(github_response.text, 'html.parser')
            github_count = github_soup.find('h3', class_='codesearch-results-header')
            if github_count:
                count_text = github_count.text.strip().split()[0].replace(',', '')
                if count_text.isdigit():
                    results.append(("GitHub", int(count_text)))
                else:
                    results.append(("GitHub", "Count not found"))
            else:
                # If we can't find the count, let's at least check if there are any results
                search_results = github_soup.find_all('li', class_='repo-list-item')
                if search_results:
                    results.append(("GitHub", f"At least {len(search_results)} repositories found"))
                else:
                    results.append(("GitHub", "No repositories found"))
        else:
            results.append(("GitHub", f"Search failed: HTTP {github_response.status_code}"))
        
        # GitLab search
        gitlab_url = f"https://gitlab.com/search?search={domain}&scope=projects&sort=relevance"
        gitlab_response = requests.get(gitlab_url, headers=headers)
        if gitlab_response.status_code == 200:
            gitlab_soup = BeautifulSoup(gitlab_response.text, 'html.parser')
            gitlab_count = gitlab_soup.find('h3', class_='gl-mt-0')
            if gitlab_count:
                count_text = gitlab_count.text.strip().split()[0].replace(',', '')
                if count_text.isdigit():
                    results.append(("GitLab", int(count_text)))
                else:
                    results.append(("GitLab", "Count not found"))
            else:
                # If we can't find the count, let's at least check if there are any results
                search_results = gitlab_soup.find_all('li', class_='project-row')
                if search_results:
                    results.append(("GitLab", f"At least {len(search_results)} projects found"))
                else:
                    results.append(("GitLab", "No projects found"))
        else:
            results.append(("GitLab", f"Search failed: HTTP {gitlab_response.status_code}"))
        
        # If both GitHub and GitLab searches fail, try an alternative method
        if all("failed" in result[1] or "not found" in result[1] for result in results):
            google_dorks = [
                f"site:github.com {domain}",
                f"site:gitlab.com {domain}"
            ]
            for dork in google_dorks:
                try:
                    search_results = list(search(dork, num_results=10))
                    platform = "GitHub" if "github.com" in dork else "GitLab"
                    results.append((platform, f"Approximately {len(search_results)} results found via Google search"))
                except Exception as e:
                    results.append((platform, f"Google search failed: {str(e)}"))
        
        return results
    except Exception as e:
        return [f"Public repository search failed: {str(e)}"]

def scan_open_ports(domain):
    try:
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            if result == 0:
                service = socket.getservbyport(port)
                open_ports.append(f"Port {port} ({service}): Open")
            sock.close()
        
        return open_ports if open_ports else ["No open ports found"]
    except Exception as e:
        return [f"Port scanning failed: {str(e)}"]

def generate_report(domain, output_path, report_type, progress_var, progress_bar):
    if report_type == 'pdf':
        pdf = PDFReport()
        pdf.set_title(f"Advanced Domain Information Report: {domain}")
    else:
        txt_content = f"Advanced Domain Information Report: {domain}\n\n"

    steps = [
        ("WHOIS Information", get_whois_info),
        ("DNS Information", get_dns_info),
        ("NSLookup Information", get_nslookup_info),
        ("Subdomains", get_subdomains),
        ("HTTP Headers", get_http_headers),
        ("SSL Information", get_ssl_info),
        ("Social Media Links", get_social_media_links),
        ("Web Technologies", get_web_technologies),
        ("Google Dorks", get_google_dorks),
        ("Email Addresses", get_email_addresses),
        ("Website Metadata", get_metadata),
        ("Certificate Transparency", get_certificate_transparency),
        ("Public Repositories", get_public_repositories),
        ("Open Ports", scan_open_ports),
    ]
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_step = {executor.submit(func, domain): (title, func) for title, func in steps}
        
        for i, future in enumerate(future_to_step):
            title, _ = future_to_step[future]
            try:
                data = future.result()
                if report_type == 'pdf':
                    pdf.add_section(title, "")
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, tuple):
                                pdf.add_key_value_pair(item[0], item[1])
                            else:
                                pdf.add_key_value_pair("Item", item)
                    elif isinstance(data, dict):
                        for key, value in data.items():
                            pdf.add_key_value_pair(key, value)
                    else:
                        pdf.add_key_value_pair("Result", str(data))
                else:
                    txt_content += f"\n{title}\n"
                    txt_content += "=" * len(title) + "\n"
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, tuple):
                                txt_content += f"{item[0]}: {item[1]}\n"
                            else:
                                txt_content += f"- {item}\n"
                    elif isinstance(data, dict):
                        for key, value in data.items():
                            txt_content += f"{key}: {value}\n"
                    else:
                        txt_content += f"{data}\n"
                    txt_content += "\n"
            except Exception as e:
                if report_type == 'pdf':
                    pdf.add_section(title, f"Error: {str(e)}")
                else:
                    txt_content += f"\n{title}\n"
                    txt_content += "=" * len(title) + "\n"
                    txt_content += f"Error: {str(e)}\n\n"
            
            # Update progress bar
            progress_var.set((i + 1) * 100 // len(steps))
            progress_bar.update()

    if report_type == 'pdf':
        pdf.output(output_path)
    else:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(txt_content)
    
    messagebox.showinfo("Report Generated", f"Advanced report saved as {output_path}")

def on_submit():
    domain = domain_entry.get()
    if domain:
        report_type = report_type_var.get()
        if report_type == 'pdf':
            file_types = [('PDF files', '*.pdf')]
            default_extension = '.pdf'
        else:
            file_types = [('Text files', '*.txt')]
            default_extension = '.txt'
        
        output_path = filedialog.asksaveasfilename(
            defaultextension=default_extension,
            filetypes=file_types,
            title="Save Report As"
        )
        
        if output_path:
            progress_var.set(0)
            progress_bar.update()
            generate_report(domain, output_path, report_type, progress_var, progress_bar)
        else:
            messagebox.showwarning("Save Cancelled", "Report generation cancelled.")
    else:
        messagebox.showwarning("Input Error", "Please enter a domain name.")

# GUI setup
root = tk.Tk()
root.title("Advanced Recon Tool")
root.configure(bg='#1C1C1C')
root.geometry('600x450')

# Title
title_label = tk.Label(root, text="ADVANCED RECON TOOL", font=("Courier", 24, 'bold'), bg='#1C1C1C', fg='#00FF00')
title_label.pack(pady=10)

# Subtitle
subtitle_label = tk.Label(root, text="Comprehensive Passive Reconnaissance Tool", font=("Courier", 12), bg='#1C1C1C', fg='#FF0000')
subtitle_label.pack(pady=5)

# Domain Input
domain_label = tk.Label(root, text="Enter Domain:", font=("Courier", 12), bg='#1C1C1C', fg='white')
domain_label.pack(pady=10)
domain_entry = tk.Entry(root, width=40, font=("Courier", 12), bg='#333333', fg='white')
domain_entry.pack(pady=5)

# Report Type Selection
report_type_var = tk.StringVar(value='pdf')
report_type_frame = tk.Frame(root, bg='#1C1C1C')
report_type_frame.pack(pady=10)

pdf_radio = tk.Radiobutton(report_type_frame, text="PDF", variable=report_type_var, value='pdf', bg='#1C1C1C', fg='white', selectcolor='#333333')
pdf_radio.pack(side=tk.LEFT, padx=10)

txt_radio = tk.Radiobutton(report_type_frame, text="TXT", variable=report_type_var, value='txt', bg='#1C1C1C', fg='white', selectcolor='#333333')
txt_radio.pack(side=tk.LEFT, padx=10)

# Progress Bar
progress_var = tk.IntVar()
progress_bar = ttk.Progressbar(root, orient='horizontal', length=400, mode='determinate', variable=progress_var)
progress_bar.pack(pady=10)

# Submit Button
submit_button = tk.Button(root, text="Generate Advanced Report", font=("Courier", 14), command=on_submit, bg='#00FF00', fg='black', width=25)
submit_button.pack(pady=20)

# Footer
footer_label = tk.Label(root, text="Use responsibly. All rights reserved.", font=("Courier", 10), bg='#1C1C1C', fg='#00FF00')
footer_label.pack(side='bottom', pady=10)

root.mainloop()
