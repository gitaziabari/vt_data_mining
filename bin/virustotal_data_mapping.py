#!/usr/bin/python

http_response_score = {"200" : 2,
                       "100" : 1,
                       "403" : 1,
                       "404" : 1
                      }


#categories could be found at https://www.forcepoint.com/master-database-url-categories
categories_score = {"blogs" : 1,
                   "uncategorized" : 0,
                   "malicious web sites": 4,              # sites containing code intentionally modify users
                   "suspicious content" : 1,              # sites with suspicious content
                   "business" : 0,
                   "known infection source" : 5,
                   "parked" : 0,
                   "phishing and other frauds" : 5,       # counterfeit legitimate sites
                   "business and economy": 0,             # Sites sponsored by or devoted to business firms
                   "travel" : 0,
                   "bot networks": 4,                     # Command and control centers
                   "parked domain": 0,                    # Sites that are expired, offered for sale, ..
                   "computersandsoftware" : 0,
                   "health" : 0,
                   "real estate" : 0,                     # Sites that provide information about renting, buying, selling
                   "information technology" : 0,          # Computers, software, the Internet and related business firms
                   "entertainment" : 0,
                   "compromised websites" : 5,            # Sites that are vulnerable and known to host an injected malicious
                   "dynamic content": 2,                  # URLs dynamically being generated
                   "not recommended site" : 3,
                   "potentially unwanted software" : 2,   # Sites altering operation of a user's hardware, software, ...
                   "web and email spam" : 2,
                   "application and software download" : 1,
                   "personal network storage and backup" : 1, #store personal files on web servers for backup or exchange
                   "hacking" : 5,
                   "hacking" : 5,
                   "elevated exposure" : 2,
                   "education" : 0,
                   "web hosting" : 0,
                   "marketing" : 0,
                   "radiomusic" : 0,
                   "internet radio and tv" : 0,
                   "videos" : 0,
                   "proxy avoidance" : 2,
                   "illegal or questionable" : 1,
                   "gambling" : 0,
                   "dynamic dns" : 3,                     # APT
}


engine_score_mapping = {
         'ALYac'               : 1,
         'AVG'                 : 1,
         'AVWARE'              : 2,
         'Ad-Aware'            : 2,
         'Aegislab'            : 0,
         'Agnitum'             : 1,
         'AhnLab-v3'           : 1,
         'Alibaba'             : 1,
         'Antiy_AVL'           : 1,
         'Arcabit'             : 0,
         'Avast'               : 0,
         'Avira'               : 1,
         'AegisLab'            : 0,
         'Baidu-international' : 1,
         'Bitdefender'         : 2,
         'Bkav'                : 0,
         'ByteHero'            : 0,
         'cat-quickhill'       : 0,
         'CMC'                 : 1,
         'ClamAV'              : 1,
         'Comodo'              : 1,
         'Cyren'               : 3,
         'DrWeb'               : 0,
         'Eset-Nod32'          : 2,
         'Emsisoft'            : 2,
         'F-Prot'              : 2,
         'F-Secure'            : 1,
         'Fortinet'            : 0,
         'Gdata'               : 2,
         'Ikarus'              : 0,
         'Jiangmin'            : 0,
         'K7AntiVirus'         : 2,
         'K7GW'                : 1,
         'Kaspersky'           : 2,
         'Kingsoft'            : 1,
         'Malwarebytes'        : 1,
         'McAfee'              : 4,
         'McAfee-GW-Edition'   : 0,
         'MicroWorld-eScna'    : 1,
         'microsoft'           : 3,
         'NANO-Antivirus'      : 1,
         'Panda'               : 1,
         'Qihoo-360'           : 0,
         'Rising'              : 0,
         'SUPERAntiSpyware'    : 1,
         'Sophos'              : 2,
         'Symantec'            : 2,
         'Tencent'             : 1,
         'TheHacker'           : 0,
         'TotalDefense'        : 1,
         'TrendMicro'          : 1,
         'TrendMicro-HouseCall': 1,
         'VBA32'               : 0,
         'VIPRE'               : 2,
         'ViROBOT'             : 1,
         'Zillya'              : 0,
         'Zoner'               : 1,
         'nProtect'            : 1,
}

