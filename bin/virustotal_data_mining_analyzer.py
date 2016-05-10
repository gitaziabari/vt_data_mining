#!/usr/local/bin/python
# coding: utf-8
import requests, json
import csv
import re, os
import urllib, urllib2
import tarfile
from functions_lib import * 
from virustotal_data_mapping import * 
from virustotal_mapping_malwarename import * 
from config_file import * 

mapping = virustotal_mapping_name()



score_threshold = 12
INTELLIGENCE_SEARCH_URL = ('https://www.virustotal.com/intelligence/search/'
                           'programmatic/')

def get_vt_file_feed():
    import requests
    date_pack = format_date_pack()
    compressed_report_path = '/tmp/file-'+date_pack+'.tar.bz2'
    params = {'apikey': vt_key, 'package': date_pack}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/feed', params=params)
    package_file = open(compressed_report_path, 'wb')
    package_file.write(response.content)
    package_file.close()
    return compressed_report_path


def get_vt_url_feed():
   import requests
   date_pack = format_date_pack()
   compressed_report_path = '/tmp/url-'+date_pack+'.tar.bz2'
   params = {'apikey': vt_key, 'package': date_pack}
   response = requests.get('https://www.virustotal.com/vtapi/v2/url/feed', params=params)
   package_file = open(compressed_report_path, 'wb')
   package_file.write(response.content)
   package_file.close()
   return compressed_report_path


def get_url_threat_score(data_info):
    count = 0
    for data in data_info:
        if data == "Response code":
           response_code = data_info.get(data)
           score = get_score(str(response_code), http_response_score)
           count+=score
        elif data == "categories":
           threat_categories = data_info.get(data)
           for category in threat_categories:
               score = get_score(category, categories_score)
               count+=score
    return count

def get_score(key, table_score):
    score = 0
    if key  in table_score:
       score = table_score.get(key)
    return score

def process_package(package_path):
  package_lib = []
  with tarfile.open(package_path, mode='r:bz2') as compressed:
    for member in compressed.getmembers():
      member_file = compressed.extractfile(member)
      for line in member_file:
        item_json = line.strip('\n')
        if not item_json:
          continue
        item_report = json.loads(item_json)
        package_lib.append(item_report)
  return package_lib


def get_av_engine_score(scan_report):
    '''get AV engine score, scoring is done based on stats available at https://www.virustotal.com/intelligence/statistics/
       you could modify the scoring per your preference'''
    av_score = 0
    val = get_sources(scan_report)
    for av_engine in val:
       if av_engine in engine_score_mapping:
          av_score+= engine_score_mapping[av_engine]
       else:
          av_score+=1
    return av_score


def get_av_engine_score_vti_search_report(scan_report):
    #VTI search return scans in the format of {av: signature,...}
    av_score = 0
    for av_engine in scan_report:
       if av_engine in engine_score_mapping:
          av_score+= engine_score_mapping[av_engine]
       else:
          av_score+=1
    return av_score


def collect_data_in_csv_format(md5, file_path):
    '''write hashes with mid level of malicious in a csv file'''
    report = get_report_all_info(md5)
    sha256 = report.get("sha256")
    file_type = report.get("filetype")
    mal_type, malware_name = mapping.create_malware_name(report, file_type)
    if (malware_name == None or malware_name == ""):
       return

    file_exists = os.path.isfile(file_path)
    if  file_exists:
           boolian = bool_exist_in_data(md5, file_path)
           if boolian == True:
              print md5+" already exists in feeds."
              return
    with open(file_path, 'a') as csvfile:
             fieldnames = ['md5', 'mwname', 'mwtype']
             writer = csv.DictWriter(csvfile, delimiter=',', lineterminator='\n', fieldnames=fieldnames)
             if not file_exists:
                writer.writeheader()
             writer.writerow({'md5': md5, 'mwname': malware_name, "mwtype":mal_type})


def bool_exist_in_data(md5, file_path):
    boolian = False
    file_exists = os.path.isfile(file_path)
    if not file_exists:
       return False
    fmap = open(file_path, 'r')
    reader = csv.DictReader(fmap)
    for item in reader:
        for key in item:
           if key == "md5":
              md5_hash = item.get(key)
              if md5 == md5_hash:
                 return True
    return boolian


def get_report_all_info(md5):
    import requests
    report_dict = {}
    params = {'resource': md5, 'apikey': vt_key, 'allinfo': 1}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    response_json = response.json()
    for key in response_json:
        if key == "positives":
           positives = response_json.get(key)
           report_dict.setdefault("positives", positives)
        elif key == "total":
           total = response_json.get(key)
           report_dict.setdefault("total", total)
        elif key =="scans":
           scans = response_json.get(key)
           sources = get_sources(scans)
           report_dict.setdefault("scans", sources)
        elif key == "md5":
           md5 = response_json.get(key)
           report_dict.setdefault("md5", md5)
        elif key == "sha1":
           sha1 = response_json.get(key)
           report_dict.setdefault(key, sha1)
        elif key == "sha256":
           sha256 = response_json.get(key)
           report_dict.setdefault(key, sha256)
        elif key == "permalink":
           permalink = response_json.get(key)
           report_dict.setdefault(key, permalink)
        elif key == "first_seen":
           first_seen = response_json.get(key)
           report_dict.setdefault(key, first_seen)
        elif key == "scan_date":
           scan_date = response_json.get(key)
           report_dict.setdefault(key, scan_date)
        elif key == "additional_info":
           file_type = None
           info = response_json.get(key)
           for i in info:
               if i =="exiftool":
                  exit_fool = info.get(i)
                  for file_info in exit_fool:
                       if file_info == "FileType":
                          file_type = exit_fool.get("FileType")
                
           report_dict.setdefault("filetype", file_type)
        else:
           continue
    return report_dict


def get_sources(scans):
    engine_lst = {}
    for vt_engine in scans:
        vdict = scans.get(vt_engine)
        if not isinstance(vdict, dict):
          continue
        detected = vdict.get("detected")
        if detected == True:
           result = vdict.get("result")
           engine_lst.setdefault(vt_engine, result)
    return engine_lst


def get_matching_files(search, page=None):
  response = None
  page = page or 'undefined'
  attempts = 0
  trid = search.get("type")
  search = get_search_in_string(search)
  parameters = {'query': search, 'apikey': vt_key, 'page': page, 'trid': trid}
  data = urllib.urlencode(parameters)
  request = urllib2.Request(INTELLIGENCE_SEARCH_URL, data)
  while attempts < 10:
    try:
      response = urllib2.urlopen(request).read()
      break
    except Exception:
      attempts += 1
      time.sleep(1)
  if not response:
    return (None, None)

  try:
    response_dict = json.loads(response)
  except ValueError:
    return (None, None)

  if not response_dict.get('result'):
    raise InvalidQueryError(response_dict.get('error'))

  next_page = response_dict.get('next_page')
  hashes = response_dict.get('hashes', [])
  return (next_page, hashes)


def get_search_in_string(search):
    search_string = ""
    for key in search:
       if key =="type":
          search_string+=key+':"'+search.get(key)+'" '
       elif key =="positives":
          search_string+=key+':'+search.get(key)+' '
       elif key == "lang":
          search_string+=key+':'+search.get(key)+' '
       elif key == "url":
          search_string+=key+':"'+search.get(key)+'" '
       elif key == "itw":
          search_string+=key+':"'+search.get(key)+'" '
       elif key == "traffic":
          search_string+=key+':"'+search.get(key)+'" '
       elif key == "tag":
          search_string+=key+':"'+search.get(key)+'" '
       elif key == "behaviour":
          search_string+=key+':"'+search.get(key)+'" '
    return search_string

def get_detected_engine_list(engines):
    engine_lst = []
    for engine in engines:
        info = engines.get(engine)
        for key in info:
            if key == "detected":
               val = info.get(key)
               if val == True:
                  engine_lst.append(engine)
    return engine_lst


def get_engine_score(engine_lst):
    count = 0
    for engine in engine_lst:
        if engine in engine_score_mapping:
           score = engine_score_mapping.get(engine)
           count+=score
        else:
           count+=1
    return count


def get_short_url(url):
    """Return top two domain levels from URI"""
    re_3986_enhanced = re.compile(r"""
        # Parse and capture RFC-3986 Generic URI components.
        ^                                    # anchor to beginning of string
        (?:  (?P<scheme>    [^:/?#\s]+): )?  # capture optional scheme
        (?://(?P<authority>  [^/?#\s]*)  )?  # capture optional authority
             (?P<path>        [^?#\s]*)      # capture required path
        (?:\?(?P<query>        [^#\s]*)  )?  # capture optional query
        (?:\#(?P<fragment>      [^\s]*)  )?  # capture optional fragment
        $                                    # anchor to end of string
        """, re.MULTILINE | re.VERBOSE)
    result = ""
    m_uri = re_3986_enhanced.match(url)
    if m_uri and m_uri.group("authority"):
        auth = m_uri.group("authority")
        paths = m_uri.group("path")
        path = paths.split("/")
        path = filter(lambda s: len(s) > 0, path)
        path_length = len(path)
        count = 1
        url_path = ""
        if path_length> 1:
           if re.search(path[1], ".exe"):
              url_path = path[0]
           else:
              url_path = path[0]+"/"+path[1]

        scheme = m_uri.group("scheme")
        result = auth+"/"+url_path
    return result

def get_url_from_data_file(data_file):
    url_lst = []
    file_exists = os.path.isfile(data_file)
    if not file_exists:
       return url_lst
    fmap = open(data_file, 'r')
    reader = csv.DictReader(fmap)
    for item in reader:
       url = item.get("indicator")
       if url in url_lst:
             continue
       url_lst.append(url)

    fmap.close()
    return url_lst


def collect_url_in_csv_format(data_file, short_url, url):
    trusted_domain_check = bool_check_whitelist(url)
    if trusted_domain_check:
       return
    file_exists = os.path.isfile(data_file)
    with open(data_file, 'a') as csvfile:
         fieldnames = ["type", "indicator"]
         writer = csv.DictWriter(csvfile, delimiter=',', lineterminator='\n', fieldnames=fieldnames)
         if not file_exists:
              writer.writeheader()
         writer.writerow({"type": "url" , "indicator": short_url.strip("\n")})
    

def bool_check_whitelist(url):
    truseted_vendors= "/work/data_mining_isoi/bin/trusted_vendors.csv"
    domain = get_domain(url)
    reader = csv.DictReader(truseted_vendors)
    for item in reader:
        if item == "indicator":
           trusted_domain = item.split("*.")[1]
           if re.search(domain, trusted_domain):
              return True
    return False


def get_domain(url):
    """Return top two domain levels from URI"""
    re_3986_enhanced = re.compile(r"""
        # Parse and capture RFC-3986 Generic URI components.
        ^                                    # anchor to beginning of string
        (?:  (?P<scheme>    [^:/?#\s]+): )?  # capture optional scheme
        (?://(?P<authority>  [^/?#\s]*)  )?  # capture optional authority
             (?P<path>        [^?#\s]*)      # capture required path
        (?:\?(?P<query>        [^#\s]*)  )?  # capture optional query
        (?:\#(?P<fragment>      [^\s]*)  )?  # capture optional fragment
        $                                    # anchor to end of string
        """, re.MULTILINE | re.VERBOSE)
    re_domain =  re.compile(r"""
        # Pick out top two levels of DNS domain from authority.
        (?P<domain>[^.]+\.[A-Za-z]{2,6})  # $domain: top two domain levels.
        (?::[0-9]*)?                      # Optional port number.
        $                                 # Anchor to end of string.
        """,
        re.MULTILINE | re.VERBOSE)
    result = ""
    m_uri = re_3986_enhanced.match(url)
    if m_uri and m_uri.group("authority"):
        auth = m_uri.group("authority")
        m_domain = re_domain.search(auth)
        if m_domain and m_domain.group("domain"):
            result = m_domain.group("domain");
    return result     


if __name__ == '__main__':
   md5 = "928e0d04292405ef823337e8612a1ce2"
   bb = collect_data_in_csv_format(md5, "/tmp/1.csv")
   print bb




