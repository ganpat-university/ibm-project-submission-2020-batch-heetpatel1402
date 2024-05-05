import requests
from bs4 import BeautifulSoup
from stem import Signal
from stem.control import Controller

def create_tor_client_domain():
    try:
        with Controller.from_port(port=9150) as controller:
            controller.authenticate(password='')
            controller.signal(Signal.NEWNYM)
    except Exception as e:
        print(f"Failed to create Tor client: {e}")

def check_onion_url_domain(url):
    create_tor_client_domain()
    try:
        with requests.Session() as session:
            session.proxies = {'http': 'socks5h://localhost:9150', 'https': 'socks5h://localhost:9150'}
            response = session.get(url)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                links = [link.get('href') for link in soup.find_all('a')]
                active_subdomains = []
                for link in links:
                    try:
                        response = session.get(link)
                        if response.status_code == 200:
                            active_subdomains.append(link)
                    except:
                        pass
                return '\n'.join(active_subdomains)
            else:
                return f"Failed to connect to the .onion URL. Status code: {response.status_code}"
    except Exception as e:
        return f"An error occurred: {e}"    
