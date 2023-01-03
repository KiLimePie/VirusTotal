import re
import os
import requests
import virustotal3


with open("top_100.txt") as f:
    top100=f.readlines()
    top100=[x.strip() for x in top100]

with open("traffic_log.txt") as f:
    trafficlog=f.readlines()

with open("artifacts.txt") as f:
    artifacts=f.read()

domain=[]
ip=[]

for line in trafficlog:
    domain.append(line.split(" ")[5].split(":")[1].strip())
    ip.append(line.split(" ")[4].split(":")[1].strip())

domain=[for x in domain if x not in top100]

p=re.compile("([a-fA-F\d]{32})")

hashes=p.findall(artifacts)

head={"x-apikey":"(YOUR API KEY HERE)"}

ioc=domain+ip+hashes
result=[]

for i in ioc:
    url=f"https://virustotal.com/api/v3/search?query={i}"
    res=requests.get(url,headers=head)
    result.append((i,res.json()))

for i,res in result:
    mal=res["data"][0]["attributes"]["last_analysis_stats"]["malicious"]
    name=res["data"][0]["links"]["self"]

    if mal>=1:
        print(f"IOC: {i}")
        print(f"Query URL: {name}")
        print(f"Malicious: {mal}")
        print()
