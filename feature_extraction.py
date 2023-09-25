import re
import requests
import json
import ipaddress
from urllib.parse import urlparse, parse_qs, urlsplit
from datetime import date
from bs4 import BeautifulSoup
import whois
import tldextract
from googlesearch import search


def extract_features(url):
    features = {}
    
    # length_url
    features['length_url'] = len(url)
    
    # length_hostname
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    whois_response = whois.whois(domain)
    features['length_hostname'] = len(parsed_url.netloc)
    
    # ip
    try:
        ipaddress.ip_address(url)
        features['ip'] = 1
    except:
        features['ip'] = 0
    
    # nb_dots
    features['nb_dots'] = url.count('.')
    
    # nb_qm
    features['nb_qm'] = url.count('?')
    
    # nb_eq
    features['nb_eq'] = url.count('=')
    
    # nb_slash
    features['nb_slash'] = url.count('/')
    
    # nb_www
    features['nb_www'] = int('www' in url)
    
    # ratio_digits_url
    digits_url = sum(c.isdigit() for c in url)
    features['ratio_digits_url'] = digits_url / len(url)
    
    # ratio_digits_host
    digits_host = sum(c.isdigit() for c in parsed_url.netloc)
    features['ratio_digits_host'] = digits_host / len(parsed_url.netloc)
    
    # tld_in_subdomain
    ext = tldextract.extract(parsed_url.netloc)
    features['tld_in_subdomain'] = int(ext.suffix in ext.subdomain)
    
    # prefix_suffix
    features['prefix_suffix'] = int(re.search(r'-|_', url) is not None)
    
    # Shortest word in hostname
    hostname_words = parsed_url.netloc.split('.')
    shortest_word_host = min(hostname_words, key=len)
    features['shortest_word_host'] = len(shortest_word_host)

    # Longest words raw
    alphanumeric_substrings = re.split(r'[^a-zA-Z0-9]+', url)
    longest_alphanumeric_substring = max(alphanumeric_substrings, key=len, default="")
    longest_length = len(longest_alphanumeric_substring)
    features["longest_words_raw"]= longest_length

    # Longest word in path
    parsed_url = urlsplit(url)
    path = parsed_url.path
    alphanumeric_substrings = re.split(r'[^a-zA-Z0-9]+', path)
    longest_alphanumeric_substring = max(alphanumeric_substrings, key=len, default="")
    longest_length = len(longest_alphanumeric_substring)
    features["longest_word_path"]= longest_length

    # Number of phish hints
    hints = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view']
    count = 0
    for hint in hints:
        count += url.lower().count(hint)
    features["phish_hints"] = count

    # nb_hyperlinks and ratio_intHyperlinks
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        def is_internal(link):
            return link.startswith('/') or urlparse(link).netloc == urlparse(url).netloc

        href_links = soup.find_all('a', href=True)
        link_tags = soup.find_all('link', href=True)
        img_tags = soup.find_all('img', src=True)
        form_tags = soup.find_all('form', action=True)
        css_tags = soup.find_all('link', rel="stylesheet")
        favicon_link = soup.find('link', rel="icon")

        # Extract href and src attributes from various tags
        href_links = [link['href'] for link in href_links]
        link_hrefs = [link['href'] for link in link_tags]
        img_srcs = [img['src'] for img in img_tags]
        form_actions = [form['action'] for form in form_tags]
        css_hrefs = [css['href'] for css in css_tags]
        favicon_href = favicon_link['href'] if favicon_link else ''

        all_links = href_links + link_hrefs + img_srcs + form_actions + css_hrefs + [favicon_href]
        internal_links = [link for link in all_links if is_internal(link)]

        if len(all_links) == 0:
            features["nb_hyperlinks"] = 0
            features["ratio_intHyperlinks"] = 0
        else:
            features["nb_hyperlinks"] = len(all_links)
            features["ratio_intHyperlinks"] = len(internal_links) / len(all_links)

    except Exception as e:
        features["nb_hyperlinks"] = 0
        features["ratio_intHyperlinks"] = 0

    # empty_title and domain_in_title
    try:
        title_tag = soup.find('title')

        empty_title = 0
        domain_in_title = 0

        if title_tag is not None:
            if not title_tag.string or title_tag.string.strip() == "":
                empty_title = 1

        if title_tag is not None:
            parts = domain.split('.')
            for part in parts:
                proper_title = title_tag.string.lower().replace(" ", "")
                if part in proper_title:
                    domain_in_title = 1
                    break

        features["empty_title"] = empty_title
        features["domain_in_title"] = domain_in_title

    except Exception as e:
        features["empty_title"] = 0
        features["domain_in_title"] = 0

    # Domain age
    creation_date = whois_response.creation_date
    try:
        if(len(creation_date)):
            creation_date = creation_date[0]
    except:
        pass

    today  = date.today()
    age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
    if age>=6:
        features["domain_age"]=age
    else:
        features["domain_age"]=-1
    
    # Check if the website is indexed by Google
    try:
        site = search(url, 5)
        if site:
            features["google_index"] = 1
        else:
            features["google_index"] = 0
    except:
        features["google_index"] = 1
    
    # Page Rank
    url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    key = "USE YOUR API KEY HERE"
    try:
        request = requests.get(url, headers={'API-OPR':key})
        result = request.json()
        result = result['response'][0]['page_rank_integer']
        if result:
            features["page_rank"] = result
        else:
            features["page_rank"] = 0
    except:
        features["page_rank"] = -1
    

    feature_list = []
    for f in features.values():
        feature_list.append(f)
    return feature_list
