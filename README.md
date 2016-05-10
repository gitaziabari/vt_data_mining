# vt_data_mining
Mining VirusTotal for operational data and applying quality control on the obtained results.

•	The tool helps you to mine the most malicious hashes and URLs among what exist in VirusTotal.
•	The obtained data could be used in threat analysis research or to feed your Cucko Sandbox.

Tools:

There are three scripts for mining data from virus total:
1.	virustotal_data_mining_file.py: It mines data based on live File feed API.
2.	virustotal_data_mining_vti_search.py: It mines data based on the applied vti search
3.	virustotal_data_mining_url.py: It mines data based on live URL feed API.

How to run the tools

Open confilg_file.py and add the following data in it to be able to run the scripts:

1.	vt_key: You would need to obtain the key from Virus Total.
2.	mid_scored_hashes: Directory to place the obtained medium scored hashes. The file needs to be in csv format.
3.	high_scored_hashes: Directory to place the obtained high scored hashes. The file needs to be in csv format.
4.	url_dir: directory to place the obtained urls. The file needs to be in csv format.
5.	Bin_dir: assign the directory of bin folder to it.
6.	search_lst: specify the criteria that you would like to use in VTI search.

Needed python modules
•	urllib2, urllib
•	json
•	requests
