import subprocess
import sys
import os

packages_to_install = {
    'flask': 'flask',
    'flask_cors': 'flask-cors',
    'bs4': 'beautifulsoup4',
    'apify_client': 'apify-client',
    'openai': 'openai',
    'requests': 'requests',
    'pandas': 'pandas',
    'web3': 'web3',
    'censys': 'censys',
    'python_dotenv': 'python-dotenv'
}

for module_name, package_name in packages_to_install.items():
    try:
        __import__(module_name)
    except ImportError:
        print(f"[*] Auto-installing {package_name}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name, "--quiet"])
from dotenv import load_dotenv
load_dotenv()  
from flask import Flask, request, jsonify, send_from_directory, make_response
from flask_cors import CORS
from bs4 import BeautifulSoup
from apify_client import ApifyClient
import openai
import requests
import pandas as pd
from web3 import Web3
from censys.search import CensysHosts
from requests.structures import CaseInsensitiveDict
import hashlib
import json

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}, r"/*": {"origins": "*"}})

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

APIFY_API_TOKEN = os.getenv("APIFY_API_TOKEN")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
NUMLOOKUP_API_KEY = os.getenv("NUMLOOKUP_API_KEY")
CENSYS_API_KEY = os.getenv("CENSYS_API_KEY")
CENSYS_SECRET_KEY = os.getenv("CENSYS_SECRET_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
INFURA_URL = os.getenv("INFURA_URL")

print("[*] Note: API keys are optional. Some features will require them.")
print(f"[*] APIFY_API_TOKEN: {'SET' if APIFY_API_TOKEN else 'NOT SET'}")
print(f"[*] OPENAI_API_KEY: {'SET' if OPENAI_API_KEY else 'NOT SET'}")

HEADERS = {"User-Agent": "Mozilla/5.0"}
client = ApifyClient(APIFY_API_TOKEN) if APIFY_API_TOKEN else None
if OPENAI_API_KEY:
    openai.api_key = OPENAI_API_KEY

MODEL = "gpt-3.5-turbo"
TEMPERATURE = 0
MAX_TOKENS = 2048

def duckduckgo_search(username, max_results=30):
    url = "https://html.duckduckgo.com/html/"
    query = (
        f'"{username}" '
        'site:instagram.com OR site:github.com OR site:twitter.com OR '
        'site:x.com OR site:facebook.com OR site:linkedin.com'
    )
    data = {"q": query}
    try:
        resp = requests.post(url, data=data, headers=HEADERS, timeout=20)
        soup = BeautifulSoup(resp.text, "html.parser")
        links = []
        for a in soup.select("a.result__a"):
            href = a.get("href")
            if href:
                links.append(href.split("?")[0])
            if len(links) >= max_results:
                break
        return list(dict.fromkeys(links))
    except Exception:
        return []

def direct_platform_probe(username):
    return {
        "instagram": [f"https://www.instagram.com/{username}/"],
        "github": [f"https://github.com/{username}"],
        "twitter": [f"https://twitter.com/{username}"],
        "facebook": [f"https://www.facebook.com/{username}"],
        "linkedin": [f"https://www.linkedin.com/in/{username}"]
    }

def detect_platforms(links):
    platforms = {"instagram": [], "github": [], "twitter": [], "facebook": [], "linkedin": []}
    for link in links:
        l = link.lower()
        if "instagram.com/" in l:
            platforms["instagram"].append(link)
        elif "github.com/" in l:
            platforms["github"].append(link)
        elif "twitter.com/" in l or "x.com/" in l:
            platforms["twitter"].append(link)
        elif "facebook.com/" in l:
            platforms["facebook"].append(link)
        elif "linkedin.com/in/" in l:
            platforms["linkedin"].append(link)
    return platforms

def extract_username_from_url(url):
    return url.rstrip("/").split("/")[-1]

def run_actor(actor_id, run_input):
    if not client:
        return {"error": "APIFY_API_TOKEN not set"}
    try:
        run = client.actor(actor_id).call(run_input=run_input)
        dataset_id = run.get("defaultDatasetId")
        if not dataset_id:
            return {"error": "No dataset created by actor"}
        items = client.dataset(dataset_id).list_items().items
        return items
    except Exception as e:
        return {"error": f"Actor execution failed: {str(e)}"}
def scrape_instagram(url):
    username = extract_username_from_url(url)
    return run_actor("apify/instagram-profile-scraper", {"usernames": [username]})

def scrape_github(url):
    username = extract_username_from_url(url)
    return run_actor("apify/github-scraper", {"usernames": [username]})

def scrape_twitter(url):
    username = extract_username_from_url(url)
    return run_actor("apify/twitter-profile-scraper", {"usernames": [username]})

def scrape_facebook(url):
    return run_actor("apify/facebook-profile-scraper", {"profileUrls": [url]})

def scrape_linkedin(url):
    return run_actor("apify/linkedin-profile-scraper", {"profileUrls": [url]})
def openai_request(prompt):
    if not OPENAI_API_KEY:
        return "OPENAI_API_KEY not set"
    try:
        response = openai.ChatCompletion.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS
        )
        return response["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Error: {str(e)}"
def censys_request(query):
    if not CENSYS_API_KEY or not CENSYS_SECRET_KEY:
        return "CENSYS keys not set"
    try:
        censyshost = CensysHosts(CENSYS_API_KEY, CENSYS_SECRET_KEY)
        results = censyshost.search(query, per_page=5, pages=2)
        return str(results.view_all())
    except Exception as e:
        return f"Error: {str(e)}"
def numlookup_request(mobilenumber):
    if not NUMLOOKUP_API_KEY:
        return {"error": "NUMLOOKUP_API_KEY not set"}
    url = f"https://api.numlookupapi.com/v1/validate/{mobilenumber}"
    headers = CaseInsensitiveDict()
    headers["apikey"] = NUMLOOKUP_API_KEY
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        return resp.json() if resp.status_code == 200 else {"error": f"Failed ({resp.status_code})"}
    except Exception as e:
        return {"error": str(e)}
def blockchain_request(network, address):
    try:
        if network == "1":  
            blockchain_url = f'https://blockchain.info/rawaddr/{address}'
            r = requests.get(blockchain_url, timeout=15)
            if r.status_code != 200:
                return {"error": f"Failed ({r.status_code})"}
            data = r.json()
            return {
                "balance": float(data.get("final_balance",0))/1e8,
                "received": float(data.get("total_received",0))/1e8,
                "sent": float(data.get("total_sent",0))/1e8
            }
        elif network == "2":  # Ethereum
            if not INFURA_URL:
                return {"error": "INFURA_URL not set"}
            web3 = Web3(Web3.HTTPProvider(INFURA_URL))
            if not web3.isConnected():
                return {"error": "Failed to connect to Ethereum node"}
            balance_wei = web3.eth.get_balance(address)
            return {"balance": str(web3.fromWei(balance_wei,"ether"))}
        else:
            return {"error": "Unsupported network"}
    except Exception as e:
        return {"error": str(e)}
def virustotal_file_scan(filepath):
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set"}
    try:
        with open(filepath,"rb") as f:
            digest = hashlib.md5(f.read()).hexdigest()
        endpoint = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': VIRUSTOTAL_API_KEY,'resource': digest}
        r = requests.get(endpoint,params=params,timeout=15)
        return r.json() if r.status_code==200 else {"error":f"VirusTotal error ({r.status_code})"}
    except FileNotFoundError:
        return {"error":"File not found"}
    except Exception as e:
        return {"error": str(e)}
def truncate_url(url, max_length=80):
    """Truncate URLs for display"""
    if isinstance(url, str) and (url.startswith('http://') or url.startswith('https://')):
        if len(url) > max_length:
            return url[:max_length] + "..."
    return url

def format_value_deep(value, indent=0):
    """Recursively format values with proper indentation and truncation"""
    spaces = "  " * indent
    
    if value is None:
        return "null"
    elif isinstance(value, bool):
        return str(value).lower()
    elif isinstance(value, (int, float)):
        return str(value)
    elif isinstance(value, str):
        if value.startswith('http://') or value.startswith('https://'):
            return truncate_url(value)
        return value[:100] + "..." if len(value) > 100 else value
    elif isinstance(value, (list, tuple)):
        if not value:
            return "[]"
        lines = []
        for i, item in enumerate(value, 1):
            if isinstance(item, dict):
                lines.append(f"{spaces}[Item {i}]")
                for k, v in item.items():
                    formatted = format_value_deep(v, indent + 1)
                    if '\n' in formatted:
                        lines.append(f"{spaces}  {k}:")
                        lines.append(formatted)
                    else:
                        lines.append(f"{spaces}  {k}: {formatted}")
            elif isinstance(item, (list, tuple)):
                lines.append(f"{spaces}- {format_value_deep(item, indent + 1)}")
            else:
                lines.append(f"{spaces}- {truncate_url(str(item))}")
        return "\n".join(lines)
    elif isinstance(value, dict):
        if not value:
            return "{}"
        lines = []
        for k, v in value.items():
            formatted = format_value_deep(v, indent + 1)
            if '\n' in formatted:
                lines.append(f"{spaces}{k}:")
                lines.append(formatted)
            else:
                lines.append(f"{spaces}{k}: {formatted}")
        return "\n".join(lines)
    else:
        return str(value)


def json_to_plaintext(json_data, title=""):
    """Convert JSON data to formatted plaintext YAML-style output"""
    output = []
    if title:
        output.append("=" * 60)
        output.append(title)
        output.append("=" * 60)
        output.append("")
    if isinstance(json_data, dict):
        for k, v in json_data.items():
            formatted = format_value_deep(v, 0)
            display_key = k.lower()
            
            if '\n' in formatted:
                output.append(f"{display_key}:")
                output.append(formatted)
            else:
                output.append(f"{display_key}: {formatted}")
            output.append("")
    else:
        output.append(str(json_data))
    
    return "\n".join(output)
@app.route("/")
def index():
    try:
        filepath=os.path.join(os.getcwd(),"index.html")
        with open(filepath,"r",encoding="utf-8") as f:
            html_content=f.read()
        resp=make_response(html_content,200)
        resp.headers['Content-Type']='text/html; charset=utf-8'
        return resp
    except Exception as e:
        return f"<h1>Error loading page: {str(e)}</h1>",500

@app.route("/test")
def test():
    return jsonify({"status":"OSINT API running","version":"1.0"})

@app.route('/scrape_social_media', methods=['POST'])
def scrape_social_media():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get('username')
    plain = data.get('plain', False)
    if not username:
        error_resp = {"error": "Username required"}
        if plain:
            resp = make_response(json_to_plaintext(error_resp, "Social Media Scraper Error"), 400)
            resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
            return resp
        return jsonify(error_resp), 400
    links = duckduckgo_search(username)
    platforms = detect_platforms(links) if links else direct_platform_probe(username)
    results = {}
    for platform, urls in platforms.items():
        if urls:
            func = globals().get(f"scrape_{platform}")
            if func:
                results[platform] = [func(url) for url in urls]
    json_response = {"username": username, "platforms": platforms, "results": results}
    if plain:
        plaintext = json_to_plaintext(json_response, f"OSINT Report for: {username}")
        resp = make_response(plaintext, 200)
        resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return resp
    return jsonify(json_response)

@app.route('/openai_query', methods=['POST'])
def openai_query():
    data = request.get_json(force=True, silent=True) or {}
    prompt = data.get('prompt')
    plain = data.get('plain', False)
    if not prompt:
        error_resp = {"error": "Prompt required"}
        if plain:
            resp = make_response(json_to_plaintext(error_resp, "OpenAI Query Error"), 400)
            resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
            return resp
        return jsonify(error_resp), 400
    response = openai_request(prompt)
    json_response = {"response": response}
    if plain:
        plaintext = json_to_plaintext(json_response, "OpenAI Response")
        resp = make_response(plaintext, 200)
        resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return resp
    return jsonify(json_response)

@app.route('/censys_search', methods=['POST'])
def censys_search():
    data = request.get_json(force=True, silent=True) or {}
    query = data.get('query')
    plain = data.get('plain', False)
    if not query:
        error_resp = {"error": "Query required"}
        if plain:
            resp = make_response(json_to_plaintext(error_resp, "Censys Search Error"), 400)
            resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
            return resp
        return jsonify(error_resp), 400
    result = censys_request(query)
    json_response = {"result": result}
    if plain:
        plaintext = json_to_plaintext(json_response, f"Censys Search Results for: {query}")
        resp = make_response(plaintext, 200)
        resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return resp
    return jsonify(json_response)

@app.route('/phone_lookup', methods=['POST'])
def phone_lookup():
    data = request.get_json(force=True, silent=True) or {}
    number = data.get('number')
    plain = data.get('plain', False)
    if not number:
        error_resp = {"error": "Phone number required"}
        if plain:
            resp = make_response(json_to_plaintext(error_resp, "Phone Lookup Error"), 400)
            resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
            return resp
        return jsonify(error_resp), 400
    result = numlookup_request(number)
    if plain:
        plaintext = json_to_plaintext(result, f"Phone Lookup Results for: {number}")
        resp = make_response(plaintext, 200)
        resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return resp
    return jsonify(result)

@app.route('/blockchain_tracker', methods=['POST'])
def blockchain_tracker():
    data = request.get_json(force=True, silent=True) or {}
    network = data.get('network')
    address = data.get('address')
    plain = data.get('plain', False)
    if not network or not address:
        error_resp = {"error": "Network and address required"}
        if plain:
            resp = make_response(json_to_plaintext(error_resp, "Blockchain Tracker Error"), 400)
            resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
            return resp
        return jsonify(error_resp), 400
    result = blockchain_request(network, address)
    if plain:
        plaintext = json_to_plaintext(result, f"Blockchain Data for: {address}")
        resp = make_response(plaintext, 200)
        resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return resp
    return jsonify(result)

@app.route('/virustotal_scan', methods=['POST'])
def virustotal_scan_route():
    data = request.get_json(force=True, silent=True) or {}
    filepath = data.get('filepath')
    plain = data.get('plain', False)
    if not filepath:
        error_resp = {"error": "File path required"}
        if plain:
            resp = make_response(json_to_plaintext(error_resp, "VirusTotal Scan Error"), 400)
            resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
            return resp
        return jsonify(error_resp), 400
    result = virustotal_file_scan(filepath)
    if plain:
        plaintext = json_to_plaintext(result, f"VirusTotal Scan Results for: {filepath}")
        resp = make_response(plaintext, 200)
        resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return resp
    return jsonify(result)
if __name__=="__main__":
    port=int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0",port=port,debug=True)
