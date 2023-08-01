import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

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
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
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

    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    def shortUrl(self):
        match = re.search(
            'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
            'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
            'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
            'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
            'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
            'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|'
            'yourls\.org|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net'
            , self.url)
        if match:
            return -1
        else:
            return 1

    def symbol(self):
        match = re.findall(r'[!@#$%^&*(),.?":{}|<>]', self.url)
        if match:
            return -1
        return 1

    def redirecting(self):
        if len(self.soup.find_all('a', href=True)) == 0:
            return -1
        elif len(self.soup.find_all('a', href=True)) > 1:
            return 0
        else:
            return 1

    def prefixSuffix(self):
        if "-" in self.url:
            return -1
        return 1

    def SubDomains(self):
        if not self.urlparse.scheme:
            self.url = "http://" + self.url
            self.urlparse = urlparse(self.url)
        if len(re.findall("\.", self.urlparse.netloc)) == 1:
            return 1
        elif len(re.findall("\.", self.urlparse.netloc)) == 2:
            return 0
        else:
            return -1

    def Hppts(self):
        if self.urlparse.scheme == "https":
            return 1
        return -1

    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            today = date.today()
            if expiration_date is None:
                return -1
            elif type(expiration_date) == list or expiration_date < today:
                return 0
            else:
                delta = expiration_date - today
                if delta.days <= 365:
                    return -1
                else:
                    return 1
        except:
            return -1

    def Favicon(self):
        if self.soup.find('link', {'rel': 'shortcut icon'}) or self.soup.find('link', {'rel': 'icon'}):
            return 1
        else:
            return -1

    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port) > 1:
                return -1
            return 1
        except:
            return -1

    def HTTPSDomainURL(self):
        if self.urlparse.scheme == 'https':
            return -1
        return 1

    def RequestURL(self):
        try:
            subDomain, domain, suffix = self.extract(self.url)
            i = urlparse(self.url).path.split('/')
            return 1
        except:
            return -1

    def AnchorURL(self):
        try:
            i = urlparse(self.url).fragment.split('/')
            if i:
                return -1
            return 1
        except:
            return -1

    def LinksInScriptTags(self):
        try:
            i = urlparse(self.url).query.split('/')
            if i:
                return -1
            return 1
        except:
            return -1

    def ServerFormHandler(self):
        if len(self.soup.find_all('form', action=True)) == 0:
            return 1
        elif len(self.soup.find_all('form', action=True)) == 1:
            return 0
        else:
            return -1

    def InfoEmail(self):
        if re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", self.url):
            return -1
        return 1

    def AbnormalURL(self):
        if self.urlparse.path == '':
            return 1
        return -1

    def WebsiteForwarding(self):
        try:
            r = requests.get(self.url)
            if len(r.history) > 1:
                return -1
            elif len(r.history) == 1:
                return 0
            else:
                return 1
        except:
            return 1

    def StatusBarCust(self):
        try:
            for img in self.soup.find_all('img', alt=True):
                if "free customisable status bar" in img['alt'].lower():
                    return -1
            return 1
        except:
            return 1

    def DisableRightClick(self):
        try:
            oncontextmenu = self.soup.find_all(True, oncontextmenu=True)
            if len(oncontextmenu) != 0:
                return -1
            return 1
        except:
            return -1

    def UsingPopupWindow(self):
        try:
            if self.soup.find_all(True, onmouseover=True):
                return -1
            elif self.soup.find_all(True, onclick=True):
                return -1
            elif self.soup.find_all(True, onmousedown=True):
                return -1
            elif self.soup.find_all(True, onmouseup=True):
                return -1
            return 1
        except:
            return 1

    def IframeRedirection(self):
        try:
            if self.soup.find_all('iframe', width=True):
                return -1
            elif self.soup.find_all('iframe', height=True):
                return -1
            elif self.soup.find_all('iframe', frameBorder=True):
                return -1
            return 1
        except:
            return 1

    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            today = date.today()
            if creation_date is None:
                return -1
            elif type(creation_date) == list:
                return 0
            else:
                delta = today - date_parse(str(creation_date))
                if delta.days <= 365:
                    return -1
                else:
                    return 1
        except:
            return -1

    def DNSRecording(self):
        try:
            for i in self.urlparse.netloc.split('.'):
                if i.isdigit():
                    return -1
            return 1
        except:
            return -1

    def WebsiteTraffic(self):
        try:
            if self.whois_response.traffic == None:
                return -1
            elif self.whois_response.traffic == False:
                return -1
            return 1
        except:
            return -1

    def PageRank(self):
        try:
            if self.whois_response.page_rank is None:
                return -1
            elif self.whois_response.page_rank == -1:
                return -1
            return 1
        except:
            return -1

    def GoogleIndex(self):
        try:
            site = search(self.url, 5)
            if site:
                return 1
            return -1
        except:
            return -1

    def LinksPointingToPage(self):
        try:
            links = self.soup.find_all('a')
            count = 0
            for link in links:
                if self.urlparse.netloc == link.get('href'):
                    count += 1
            if count == 0:
                return -1
            elif count <= 2:
                return 0
            return 1
        except:
            return -1

    def StatsReport(self):
        try:
            if self.whois_response.whois_server == None:
                return -1
            elif self.whois_response.whois_server == "":
                return -1
            return 1
        except:
            return -1

    def getFeaturesList(self):
        return self.features

    def extract(self, url):
        subDomain, domain, suffix = re.findall(
            r"[a-zA-Z0-9_//]+?://+?([a-zA-Z0-9_//.]+)/?", url)[0].split('.')
        return subDomain, domain, suffix
