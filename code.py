import requests
import os
from bs4 import BeautifulSoup
from apify_client import ApifyClient
import json
APIFY_API_TOKEN = os.getenv("APIFY_API_TOKEN")
if not APIFY_API_TOKEN:
    raise ValueError("APIFY_API_TOKEN not set in environment variables")
HEADERS = {"User-Agent": "Mozilla/5.0"}
client = ApifyClient(APIFY_API_TOKEN)
def duckduckgo_search(username, max_results=30):
    url = "https://html.duckduckgo.com/html/"
    query = (
        f'"{username}" '
        f'site:instagram.com OR site:github.com OR site:twitter.com OR '
        f'site:x.com OR site:facebook.com OR site:linkedin.com'
    )
    data = {"q": query}
    response = requests.post(url, data=data, headers=HEADERS, timeout=20)
    soup = BeautifulSoup(response.text, "html.parser")
    links = []
    for a in soup.select("a.result__a"):
        href = a.get("href")
        if href:
            links.append(href.split("?")[0])
        if len(links) >= max_results:
            break
    return list(set(links))
def direct_platform_probe(username):
    return {
        "instagram": [f"https://www.instagram.com/{username}/"],
        "github": [f"https://github.com/{username}"],
        "twitter": [f"https://twitter.com/{username}"],
        "facebook": [f"https://www.facebook.com/{username}"],
        "linkedin": [f"https://www.linkedin.com/in/{username}"]
    }
def detect_platforms(links):
    platforms = {
        "instagram": [],
        "github": [],
        "twitter": [],
        "facebook": [],
        "linkedin": []
    }
    for link in links:
        l = link.lower()
        if "instagram.com/" in l:
            platforms["instagram"].append(link)
        elif "github.com/" in l and l.count("/") == 3:
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
    run = client.actor(actor_id).call(run_input=run_input)
    dataset_id = run["defaultDatasetId"]
    return client.dataset(dataset_id).list_items().items
def print_profiles(platform, profiles):
    if not profiles:
        print(f"No public data for {platform}")
        return
    for i, profile in enumerate(profiles, 1):
        print(f"\n  🔹 {platform.upper()} PROFILE #{i}")
        for k, v in profile.items():
            if v not in ("", None, [], {}):
                print(f"     {k}: {v}")
def scrape_instagram(url):
    username = extract_username_from_url(url)
    return run_actor(
        "apify/instagram-profile-scraper",
        {"usernames": [username]}
    )
def scrape_github(url):
    username = extract_username_from_url(url)
    return run_actor(
        "apify/github-scraper",
        {"usernames": [username]}
    )
def scrape_twitter(url):
    username = extract_username_from_url(url)
    return run_actor(
        "apify/twitter-profile-scraper",
        {"usernames": [username]}
    )
def scrape_facebook(url):
    return run_actor(
        "apify/facebook-profile-scraper",
        {"profileUrls": [url]}
    )
def scrape_linkedin(url):
    return run_actor(
        "apify/linkedin-profile-scraper",
        {"profileUrls": [url]}
    )
def run_osint(username):
    print(f"\nStarting OSINT scan for: {username}")
    print("=" * 70)
    links = duckduckgo_search(username)
    if links:
        print("\n[DEBUG] DuckDuckGo links found:")
        for l in links:
            print(" ", l)
        platforms = detect_platforms(links)
    else:
        print("\nDuckDuckGo found nothing — using DIRECT PLATFORM PROBING")
        platforms = direct_platform_probe(username)
    results = {}
    if platforms["instagram"]:
        print("\nINSTAGRAM FOUND")
        results["instagram"] = []
        for url in platforms["instagram"]:
            data = scrape_instagram(url)
            results["instagram"].extend(data)
            print_profiles("instagram", data)
    if platforms["github"]:
        print("\nGITHUB FOUND")
        results["github"] = []
        for url in platforms["github"]:
            data = scrape_github(url)
            results["github"].extend(data)
            print_profiles("github", data)
    if platforms["twitter"]:
        print("\nTWITTER / X FOUND")
        results["twitter"] = []
        for url in platforms["twitter"]:
            data = scrape_twitter(url)
            results["twitter"].extend(data)
            print_profiles("twitter", data)
    if platforms["facebook"]:
        print("\nFACEBOOK FOUND")
        results["facebook"] = []
        for url in platforms["facebook"]:
            data = scrape_facebook(url)
            results["facebook"].extend(data)
            print_profiles("facebook", data)
    if platforms["linkedin"]:
        print("\nLINKEDIN FOUND")
        results["linkedin"] = []
        for url in platforms["linkedin"]:
            data = scrape_linkedin(url)
            results["linkedin"].extend(data)
            print_profiles("linkedin", data)
    report = {
        "username": username,
        "platforms_checked": platforms,
        "scraped_data": results
    }
    print("\nOSINT scan completed")
    return report
if __name__ == "__main__":
    username = input("Enter username to scan: ").strip()
    report = run_osint(username)
    filename = f"{username}_osint_report.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\nReport saved as: {filename}")
