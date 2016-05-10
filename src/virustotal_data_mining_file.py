#!/usr/local/bin/python

import sys, time

from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *


analyzer = import_from("virustotal_data_mining_analyzer")


feed_file = analyzer.get_vt_file_feed()
feed_report = analyzer.process_package(feed_file)
for feed_entry in feed_report:
    md5 = feed_entry.get("md5")
    positives = feed_entry.get("positives")
    if positives > 6:
          scan_report = feed_entry.get("scans")
          av_score = analyzer.get_av_engine_score(scan_report)
          if (av_score >=6  and av_score <10):
                analyzer.collect_data_in_csv_format(md5, mid_scored_hashes)
          elif (av_score >=10):
               analyzer.collect_data_in_csv_format(md5, high_scored_hashes)
          else:
               print "Total score of Antivirus Engines is "+str(av_score)+" and doesn't meet the minumim requirement!"

    else:
          print "Number of Antiviruses detecting hash "+md5+" malicious is only "+str(positives)+" and doesn't meet the minumim requirement!"


