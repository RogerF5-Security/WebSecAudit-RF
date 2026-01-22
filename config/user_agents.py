"""
Pool de User-Agents realistas para evasión
"""
import random

USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    # Firefox macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox Linux
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
]

def get_random_user_agent() -> str:
    """Retorna un User-Agent aleatorio"""
    return random.choice(USER_AGENTS)

def get_random_headers() -> dict:
    """Genera headers aleatorios realistas"""
    headers = {
        "User-Agent": get_random_user_agent(),
        "Accept": random.choice([
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "*/*"
        ]),
        "Accept-Language": random.choice([
            "en-US,en;q=0.9",
            "es-ES,es;q=0.9,en;q=0.8",
            "en-GB,en;q=0.9"
        ]),
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": str(random.choice([0, 1])),
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    
    # Headers opcionales aleatorios
    if random.random() > 0.5:
        headers["Sec-Fetch-Dest"] = random.choice(["document", "empty"])
        headers["Sec-Fetch-Mode"] = random.choice(["navigate", "cors"])
        headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin"])
    
    return headers