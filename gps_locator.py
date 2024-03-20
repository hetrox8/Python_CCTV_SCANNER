import requests
import random
import time

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/88.0.705.81 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "fr-FR,fr;q=0.9",
]

ACCEPT_ENCODINGS = [
    "gzip, deflate, br",
    "identity",
]

def get_gps_coordinates(device_ip, proxies=None):
    try:
        user_agent = random.choice(USER_AGENTS)
        accept_language = random.choice(ACCEPT_LANGUAGES)
        accept_encoding = random.choice(ACCEPT_ENCODINGS)

        headers = {
            'User-Agent': user_agent,
            'Accept-Language': accept_language,
            'Accept-Encoding': accept_encoding,
        }

        response = requests.get(f"https://ipinfo.io/{device_ip}/json", headers=headers, proxies=proxies, timeout=5)
        response.raise_for_status()

        data = response.json()
        if 'loc' in data:
            latitude, longitude = data['loc'].split(',')
            return float(latitude), float(longitude)
        else:
            return None, None
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"Request error occurred: {req_err}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    return None, None

def adaptive_delay():
    return random.uniform(1, 3)

def main():
    device_ip = "127.0.0.1"  # Example IP address
    proxies = {
        'http': 'http://username:password@proxy_url:proxy_port',
        'https': 'https://username:password@proxy_url:proxy_port'
    }
    while True:
        latitude, longitude = get_gps_coordinates(device_ip, proxies)
        if latitude is not None and longitude is not None:
            print(f"GPS coordinates: Latitude {latitude}, Longitude {longitude}")
        else:
            print("Failed to retrieve GPS coordinates.")
        delay = adaptive_delay()
        print(f"Delaying next request for {delay} seconds...")
        time.sleep(delay)

if __name__ == "__main__":
    main()
