#!/usr/local/bin/python

import sys, time

from config_file import * 
sys.path.append(bin_dir)
from functions_lib  import *

analyzer = import_from("virustotal_data_mining_analyzer")


package_path = analyzer.get_vt_url_feed()
url_report = analyzer.process_package(package_path)
for param in url_report:
    url_positives = param.get("positives")
    url = param.get("url")
    if url_positives > 8:
           data_report = {}
           info = param.get("additional_info")
           url_threat_score = analyzer.get_url_threat_score(info)
           engines_lst = param.get("scans")
           engines = analyzer.get_detected_engine_list(engines_lst)
           engine_score = analyzer.get_engine_score(engines)
           if engine_score > 10:
              if url_threat_score >8:
                 short_url = analyzer.get_short_url(url)
                 url_lst = analyzer.get_url_from_data_file(url_data)
                 if short_url in url_lst:
                    continue
                 analyzer.collect_url_in_csv_format(url_data, short_url, url) 
