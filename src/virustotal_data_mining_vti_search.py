#!/usr/local/bin/python

import sys, time
import sys, time

from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *

analyzer = import_from("virustotal_data_mining_analyzer")


next_page = None


for search_tbl in search_lst:
      count = 0
      while count < 4:
            count +=1      
            next_page, hashes = analyzer.get_matching_files(search_tbl, page=next_page)
            for md5 in hashes:
                report = analyzer.get_report_all_info(md5)
                if len(report) == 0:
                   continue
                positives = report.get("positives")
                if positives > 6:
                   md5 = report.get("md5")
                   for key in report :
                      if key == "scans":
                         scan_report = report.get(key)
                         av_score = analyzer.get_av_engine_score_vti_search_report(scan_report)
                         if (av_score >=6  and av_score <10):
                             analyzer.collect_data_in_csv_format(md5, mid_scored_hashes)
                         elif (av_score >=10):
                             analyzer.collect_data_in_csv_format(md5, high_scored_hashes)
  
                else:
                    print "Positives AV engines on hash "+md5+" is: "+str(positives)


