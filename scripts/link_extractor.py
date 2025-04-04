import re
import whois
from urllib.parse import urlparse
import dns.resolver
from ipwhois import IPWhois
from datetime import datetime
import requests
import socket
import ssl
import joblib
import numpy as np
import pandas as pd

def extract_url_attributes(url):
    url = re.sub(r"https?://", "", url)  

    parsed_url = urlparse(url)
    
    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query

    def count_occurrences(string, characters):
        return sum(string.count(char) for char in characters)

    shorteners = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd',
        'buff.ly', 'adf.ly', 'clck.ru', 'shorte.st', 'mcaf.ee',
        'lnkd.in', 'rb.gy', 'snip.ly', 'tr.im', 'shorturl.at',
        'bl.ink', 'cutt.ly', 'rebrand.ly', 'soo.gd', 'short.io',
        'qr.ae', '0rz.tw', 'ur1.ca', 'v.gd', 'x.co'
    ]

    attributes = {
        'qty_dot_url': int(count_occurrences(url, ['.']) > 0),
        'qty_hyphen_url': int(count_occurrences(url, ['-']) > 0),
        'qty_underline_url': int(count_occurrences(url, ['_']) > 0),
        'qty_slash_url': int(count_occurrences(url, ['/']) > 0),
        'qty_questionmark_url': int(count_occurrences(url, ['?']) > 0),
        'qty_equal_url': int(count_occurrences(url, ['=']) > 0),
        'qty_at_url': int(count_occurrences(url, ['@']) > 0),
        'qty_exclamation_url': int(count_occurrences(url, ['!']) > 0),
        'qty_space_url': int(count_occurrences(url, [' ']) > 0),
        'qty_tilde_url': int(count_occurrences(url, ['~']) > 0),
        'qty_comma_url': int(count_occurrences(url, [',']) > 0),
        'qty_plus_url': int(count_occurrences(url, ['+']) > 0),
        'qty_asterisk_url': int(count_occurrences(url, ['*']) > 0),
        'qty_hashtag_url': int(count_occurrences(url, ['#']) > 0),
        'qty_dollar_url': int(count_occurrences(url, ['$']) > 0),
        'qty_percent_url': int(count_occurrences(url, ['%']) > 0),
        'qty_tld_url': int(len(re.findall(r'\.[a-z]{2,}$', domain)) > 0),
        'qty_dot_domain': int(count_occurrences(domain, ['.']) > 0),
        'qty_hyphen_domain': int(count_occurrences(domain, ['-']) > 0),
        'qty_underline_domain': int(count_occurrences(domain, ['_']) > 0),
        'qty_slash_domain': int(count_occurrences(domain, ['/']) > 0),
        'qty_questionmark_domain': int(count_occurrences(domain, ['?']) > 0),
        'qty_equal_domain': int(count_occurrences(domain, ['=']) > 0),
        'qty_at_domain': int(count_occurrences(domain, ['@']) > 0),
        'qty_and_domain': int(count_occurrences(domain, ['&']) > 0),
        'qty_exclamation_domain': int(count_occurrences(domain, ['!']) > 0),
        'qty_space_domain': int(count_occurrences(domain, [' ']) > 0),
        'qty_tilde_domain': int(count_occurrences(domain, ['~']) > 0),
        'qty_comma_domain': int(count_occurrences(domain, [',']) > 0),
        'qty_plus_domain': int(count_occurrences(domain, ['+']) > 0),
        'qty_asterisk_domain': int(count_occurrences(domain, ['*']) > 0),
        'qty_hashtag_domain': int(count_occurrences(domain, ['#']) > 0),
        'qty_dollar_domain': int(count_occurrences(domain, ['$']) > 0),
        'qty_percent_domain': int(count_occurrences(domain, ['%']) > 0),
        'qty_vowels_domain': int(sum(1 for char in domain if char.lower() in 'aeiou') > 0),
        'domain_in_ip': int(bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', domain))),
        'server_client_domain': None,
        'qty_hyphen_params': int(count_occurrences(query, ['-']) > 0),
        'qty_slash_params': int(count_occurrences(query, ['/']) > 0),
        'qty_percent_params': int(count_occurrences(query, ['%']) > 0),
        'time_response': None,
        'domain_spf': None,
        'asn_ip': None,
        'time_domain_activation': None,
        'time_domain_expiration': None,
        'qty_ip_resolved': None,
        'qty_nameservers': None,
        'qty_mx_servers': None,
        'ttl_hostname': None,
        'tls_ssl_certificate': None,
        'qty_redirects': None,
        'url_google_index': None,
        'domain_google_index': None,
        'url_shortened': None,
    }

    try:
        whois_data = whois.whois(domain)
        if whois_data.creation_date and whois_data.expiration_date:
            activation_date = whois_data.creation_date
            expiration_date = whois_data.expiration_date
            if isinstance(activation_date, list):  
                activation_date = activation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            attributes['time_domain_activation'] = int((datetime.now() - activation_date).days > 0)
            attributes['time_domain_expiration'] = int((expiration_date - datetime.now()).days > 0)
    except:
        attributes['time_domain_activation'] = None
        attributes['time_domain_expiration'] = None

    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        attributes['qty_nameservers'] = int(len(ns_records) > 0)
    except:
        attributes['qty_nameservers'] = None

    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        attributes['qty_mx_servers'] = int(len(mx_records) > 0)
    except:
        attributes['qty_mx_servers'] = None

    if attributes['domain_in_ip']:
        try:
            ip_info = IPWhois(domain).lookup_rdap()
            attributes['asn_ip'] = 1
            attributes['qty_ip_resolved'] = 1
        except:
            attributes['asn_ip'] = None
            attributes['qty_ip_resolved'] = None
    else:
        attributes['asn_ip'] = None
        attributes['qty_ip_resolved'] = None

    try:
        google_url = f"https://www.google.com/search?q=site:{domain}"
        response = requests.get(google_url, headers={"User-Agent": "Mozilla/5.0"})
        attributes['domain_google_index'] = int('index' in response.text.lower())
        attributes['url_google_index'] = int('index' in response.text.lower())
    except:
        attributes['domain_google_index'] = None
        attributes['url_google_index'] = None

    try:
        spf_records = dns.resolver.resolve(domain, 'TXT')
        attributes['domain_spf'] = int(any('spf' in record.to_text().lower() for record in spf_records))
    except:
        attributes['domain_spf'] = None

    try:
        response = requests.get(url, allow_redirects=True)
        attributes['qty_redirects'] = int(len(response.history) > 0)
    except:
        attributes['qty_redirects'] = None

    try:
        start_time = datetime.now()
        requests.get(url)
        end_time = datetime.now()
        attributes['time_response'] = int((end_time - start_time).microseconds > 0)
    except:
        attributes['time_response'] = None

    try:
        answer = dns.resolver.resolve(domain)
        attributes['ttl_hostname'] = int(answer.rrset.ttl > 0)
    except:
        attributes['ttl_hostname'] = None

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                attributes['tls_ssl_certificate'] = 1
    except:
        attributes['tls_ssl_certificate'] = None


    try:
        socket.gethostbyname(domain)
        attributes['server_client_domain'] = 1
    except:
        attributes['server_client_domain'] = None

    return attributes

model_path = "model\Phishing_Model.pkl"
model = joblib.load(model_path)

# Load feature names from training
feature_names_path = "model\Feature_Names.pkl"
feature_names = joblib.load(feature_names_path)

def pred(url):
    attributes = extract_url_attributes(url)


    attributes = {key: 0 if value is None else int(value) for key, value in attributes.items()}

    # Convert to DataFrame
    df_single = pd.DataFrame([attributes])

    df_single = df_single.reindex(columns=feature_names, fill_value=0)

    # Predict
    prediction = model.predict(df_single)
    
    return int(prediction[0])  # Convert prediction to integer (0 or 1)

# Test
if __name__ == "__main__":
    url = input("Enter URL: ")
    prediction = pred(url)
    if prediction == 1:
        print("Phishing")
    else:
        print("Legitimate")    