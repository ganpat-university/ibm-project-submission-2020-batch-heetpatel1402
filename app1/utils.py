from urllib.parse import urlparse
import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from stem import Signal
from stem.control import Controller
import re
import ipaddress
import whois
import google
from datetime import date
from .models import URL
from django.conf import settings
# from sklearn.externals import joblib1

# Load your trained model

clf = RandomForestClassifier(n_estimators=100)

# Load dataset
file_path = 'F:\\college\\sem 7\\tor\\tor project\\phishingg.csv'
try: 
    data = pd.read_csv(file_path)
    print("Dataset loaded successfully.")
    # Now 'data' contains your dataset, and you can perform operations on it.
except FileNotFoundError:
    print(f"Error: File '{file_path}' not found.")
except Exception as e:
    print(f"An error occurred: {e}")

# Split data for training
y1 = data['class']
X1 = data.drop('class', axis=1)
x1_train, x1_test, y1_train, y1_test = train_test_split(X1, y1, test_size=0.1, random_state=100)

# Train the model
clf.fit(x1_train, y1_train)


# clf = load_model()

# class FeatureExtraction:
#     features = []

#     def __init__(self, url):
#         # Your feature extraction code here...

class FeatureExtraction:
    features = []
    
    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Https())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        # Add the rest of your feature extraction methods here
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # Define your feature extraction methods here
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2.longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    # 3.shortUrl
    def shortUrl(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',
                          self.url)
        if match:
            return -1
        return 1

    # 4.Symbol@
    def symbol(self):
        if re.findall("@", self.url):
            return -1
        return 1



    # 5.Redirecting//
    def redirecting(self):
        if self.url.rfind('//') > 6:
            return -1
        return 1

    # 6.prefixSuffix
    def prefixSuffix(self):
        try:
            match = re.findall('\-', self.domain)
            if match:
                return -1
            return 1
        except:
            return -1

    # 7.SubDomains
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8.HTTPS
    def Https(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https:
                return 1
            return -1
        except:
            return 1

    # 9.DomainRegLen
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            try:
                if (len(expiration_date)):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if (len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            age = (expiration_date.year - creation_date.year) * 12 + (
                        expiration_date.month - creation_date.month)
            if age >= 12:
                return 1
            return -1
        except:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or self.domain in head.link['href']:
                        return 1
            return -1
        except:
            return -1

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port) > 1:
                return -1
            return 1
        except:
            return -1

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            if 'https' in self.domain:
                return -1
            return 1
        except:
            return -1

    # 13. RequestURL
    def RequestURL(self):
        try:
            success, i = 0, 0
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            try:
                percentage = success / float(i) * 100
                if percentage < 22.0:
                    return 1
                elif ((percentage >= 22.0) and (percentage < 61.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # 14. AnchorURL
    def AnchorURL(self):
        try:
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                        self.url in a['href'] or self.domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1

            try:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    return 1
                elif ((percentage >= 31.0) and (percentage < 67.0)):
                    return 0
                else:
                    return -1
            except:
                return -1

        except:
            return -1

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            i, success = 0, 0

            for link in self.soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for script in self.soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            try:
                percentage = success / float(i) * 100
                if percentage < 17.0:
                    return 1
                elif ((percentage >= 17.0) and (percentage < 81.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            if str(self.response.headers['Server']):
                return -1
            else:
                return 1
        except:
            return 1

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            if 'info@' in self.url or 'admin@' in self.url or 'support@' in self.url or 'noreply@' in self.url or 'contact@' in self.url:
                return -1
            return 1
        except:
            return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            if 'http://about' in self.url:
                return -1
            return 1
        except:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if re.findall(r'=', self.urlparse.query):
                return -1
            return 1
        except:
            return -1

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            if 'window.status' in self.soup.find_all('script'):
                return -1
            return 1
        except:
            return -1

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            if "oncontextmenu" in self.soup.find_all('body'):
                return -1
            return 1
        except:
            return -1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if "target=_blank" in self.soup.find_all('a', href=True):
                return -1
            return 1
        except:
            return -1

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            if "frameBorder" in self.soup.find_all('iframe', width=True) or "frameBorder" in self.soup.find_all(
                    'iframe', height=True):
                return -1
            return 1
        except:
            return -1

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if (len(creation_date) > 1):
                    creation_date = creation_date[0]
                today = date.today()
                age = today.year - creation_date.year - (
                            (today.month, today.day) < (creation_date.month, creation_date.day))
                if age >= 6:
                    return -1
                return 1
            except:
                return 1
        except:
            return -1

    # 25. DNSRecording
    def DNSRecording(self):
        try:
            dns = self.whois_response.name_servers
            if dns == None:
                return 1
            return -1
        except:
            return -1

    # 26. WebsiteTraffic
    def WebsiteTraffic(self):
        try:
            if self.whois_response.traffic == None:
                return 1
            return -1
        except:
            return -1

    # 27. PageRank
    def PageRank(self):
        try:
            if self.whois_response.page_rank == None:
                return 1
            return -1
        except:
            return -1

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            if self.whois_response.indexed_google == None:
                return 1
            return -1
        except:
            return -1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            if self.whois_response.links_pointing_to_page == None:
                return 1
            return -1
        except:
            return -1

    # 30. StatsReport
    def StatsReport(self):
        try:
            if self.whois_response.stats_report == None:
                return 1
            return -1
        except:
            return -1
      
def create_tor_client():
    try:
        with Controller.from_port(port=9150) as controller:
            controller.signal(Signal.NEWNYM)
    except Exception as e:
        print(f"Failed to create Tor client: {e}")

def check_onion_url(url):
    create_tor_client()
    try:
        onion_links = []
        with requests.Session() as session:
            session.proxies = {'http': 'socks5h://localhost:9150', 'https': 'socks5h://localhost:9150'}
            response = session.get(url)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                links = [link.get('href') for link in soup.find_all('a')]
                for link in links:
                    try:
                        response = session.get(link)
                        if response.status_code == 200:
                            onion_links.append(link)
                    except:
                        pass
                return onion_links
            else:
                print(f"Failed to connect to the .onion URL. Status code: {response.status_code}")
                return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []
