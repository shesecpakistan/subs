#!/bin/bash

echo "==============> QUICK sub Tool Running on $1"
curl -s https://crt.sh/?q=%.$1  | sed 's/<\/\?[^>]\+>//g' | grep $1 | sort -u >> domains.txt
curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1 >> domains.txt
curl -s https://api.hackertarget.com/hostsearch/?q=$1 | cut -d',' -f1 | sort -u | grep $1 >> domains.txt
curl -s https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1 | jq -r '.subdomains | .[]' | sort -u >> domains.txt
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$1/*&output=text&fl=original&collapse=urlkey" |sort| sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | uniq | grep $1 >> domains.txt
curl -s "https://dns.bufferover.run/dns?q=."$1 | jq -r .FDNS_A[]|cut -d',' -f2|sort -u >> domains.txt
curl -s  -X POST --data "url=$1&Submit1=Submit" https://suip.biz/?act=findomain | grep $1 | cut -d ">" -f 2 | awk 'NF' | tail -n +2 | sed '$d' >> domains.txt
curl -s  -X POST --data "url=$1&Submit1=Submit" https://suip.biz/?act=amass | grep $1 | cut -d ">" -f 2 | awk 'NF' >> domains.txt
curl -iLs -w "\n%{http_code}" https://api.recon.dev/search?domain=$1 -A "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0" | jq .[].domain | grep $1 >> domains.txt
curl -s  -X POST --data "url=$1&Submit1=Submit" https://suip.biz/?act=subfinder | grep $1 | cut -d ">" -f 2 | awk 'NF' >> domains.txt
curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep -oaEi "https?://[^\"\\'> ]+" | grep $1 | cut -d "/" -f3 | sort -u >> domains.txt
curl -s "https://riddler.io/search/exportcsv?q=pld:$1"| grep -o "\w.*$1"|awk -F, '{print $6}'|sort -u >> domains.txt
curl -s "https://api.threatminer.org/v2/domain.php?q=$1&rt=5" | jq -r '.results[]' 2>/dev/null |grep -o "\w.*$1"|sort -u >> domains.txt
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$1/passive_dns"|jq '.passive_dns[].hostname' 2>/dev/null |grep -o "\w.*$1"|sort -u >> domains.txt
curl -s "https://www.virustotal.com/ui/domains/$1/subdomains?limit=40"|jq -r '.' 2>/dev/null |grep id|grep -o "\w.*$1"|cut -d '"' -f3|egrep -v " " >> domains.txt
curl -s "https://jldc.me/anubis/subdomains/$1" | jq -r '.' 2>/dev/null | grep -o "\w.*$1" >> domains.txt
curl -iLs "https://$1.tld/v2/swagger.json" -A "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0" | jq '.paths | keys[]' >> domains.txt


echo "==============> Sorting"
cat domains.txt | sed 's/ //g' | grep $1 | sort | uniq | sed 's/ //g' | sed 's/*//' | sed 's/^\.//' | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" | sed "/'$/d" | sed '/crt/d' | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" | sort -u >> out.txt
cat out.txt | unfurl domains | sort -u >> $1-sub.txt
rm domains.txt out.txt
echo "Quicks subs are $(cat $1-sub.txt | wc -l)"
