import requests, zipfile, io, json


host = "wpt23243"
target = "cisco"


print(" Downloading zip file.....")
r = requests.get('https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2018.json.zip')
print("Processing zip.....")
z = zipfile.ZipFile(io.BytesIO(r.content))
z.extractall()
print(z.namelist())
print("Reading file contents.....")
f = z.open(z.namelist()[0])
content = f.read()
print("Parsing JSON....")
json_data = json.loads(content)
print("Start loop....")
for cve in json_data["CVE_Items"]:

    if len(cve["cve"]["affects"]["vendor"]["vendor_data"])>0:
        #static index 0 -- more than 1 vendor?
        vendor_name =cve["cve"]["affects"]["vendor"]["vendor_data"][0]["vendor_name"]


        #static index 0 - more than 1 product per vendor?
        product = cve["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]
        product_name = product["product_data"][0]["product_name"]
        description = cve["cve"]["description"]["description_data"][0]["value"]
        impact = cve["impact"]["baseMetricV3"]
        vector = impact["cvssV3"]["attackVector"]
        severity = impact["cvssV3"]["baseSeverity"]
        product_name = product_name.lower()
        target = target.lower()
        description = description.lower()
        #will need to do plenty of data massaging
        #product names contain special characters and inconsitent formatting
        #May also need to find 'description' and do searching there
        #more of an art than science.
        if target in product_name or target in description:
            print(cve["cve"]["CVE_data_meta"]["ID"])
            print("   " + vendor_name)
            print("      - " + product_name)
            print("Vector: "+vector)
            print("Severity: "+severity)
            print("Description: "+description)
            print("")
            print("")
            print("")
