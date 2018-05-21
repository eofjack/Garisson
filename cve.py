import requests, zipfile, io, json, time, re

class software:
    vendor = ""
    product = ""
    version = ""
    cve = []

    def __str__(self):
        return self.vendor+" - "+self.product+" - "+self.version

sw_list = []


def uniform_vendor(vendor_name):
    vendor_name = vendor_name.lower()
    vendor_name = vendor_name.replace("corporation","")
    vendor_name = vendor_name.replace("llc","")
    vendor_name = vendor_name.replace("  ","")
    return vendor_name

def uniform_product(product_name):
    print(product_name)
    product_name = product_name.replace("-"," ")
    product_name = product_name.replace("_"," ")
    product_name = product_name.replace("(64-bit)"," ")
    product_name = product_name.replace("(32 bit)"," ")
    product_name = product_name.replace("x86"," ")
    product_name = product_name.replace("x64"," ")
    product_name = product_name.replace("en-US"," ")
    product_name = product_name.replace("en US"," ")
    product_name = product_name.replace(" v."," ")
    product_name = product_name.replace("(remove only)"," ")
    product_name = re.sub(r"\d+\.\d+\.\d+\.\d+"," ",product_name)
    product_name = re.sub(r"\d+\.\d+\.\d+"," ",product_name)
    product_name = re.sub(r"\d+\.\d+"," ",product_name)
    product_name = re.sub(r"\s+"," ",product_name)
    product_name = product_name.lower()
    print(product_name)
    return product_name




#Searches CVE for a software match.
# Param:
#   software - a software obect
#   vendor, produt, version - string
#   scope - how strict to match. string: vendor|product|version.
#       if version: vendor, product & version need to match
#       if product: vendor & product need to match
#       if vendor: vendor needs to match
# Returns:
#   match_type - string: exact|loose|none
def find_sw_in_cve(sw, vendor, product, version, cve_desc, vendor_match = True, product_match=True, version_match=True):
    sw_match = match_sw(sw, vendor=vendor, product=product, version=version, vendor_match=vendor_match,
                        product_match=product_match, version_match=version_match)

    #Couldnt find match. Check CVE Description.
    if sw_match == "none":
        if sw.product in cve_desc.lower():
            return "loose"
    return sw_match


# Soley for matching vendor, product and version with known software.
# Param:
#   software - a software obect
#   vendor, produt, version - string
#   scope - how strict to match. string: vendor|product|version.
#       if version: vendor, product & version need to match
#       if product: vendor & product need to match
#       if vendor: vendor needs to match
# Returns:
#   match_type - string: exact|loose|none
def match_sw(sw, vendor, product, version, vendor_match = True, product_match=True, version_match=True):
    vendor = vendor.lower()
    vm = False

    product = product.lower()
    pm = False

    version = version.lower()
    vem = False

    loose = False


    if vendor_match and (len(sw.vendor) > 0 and len(vendor) > 0):
        if vendor == sw.vendor:
            vm = True
        if " "+vendor+" " in sw.vendor or " "+sw.vendor+" " in vendor:
            vm = True
            loose = True
    if product_match and (len(sw.product) > 0 and len(product) > 0):
        if product == sw.product:
            pm = True
        if " "+product+" " in sw.product or " "+sw.product+" " in product:
            pm = True
            loose = True
    if version_match and (len(sw.version) > 0 and len(version) > 0):
        if version == sw.version:
            vem = True
        if " "+version+" " in sw.version or " "+sw.version+" " in version:
            vem = True
            loose = True

    success = False
    if (vem and pm and vm) and (product_match and vendor_match and version_match):
        success = True
    elif (pm and vm) and (product_match and vendor_match and version_match == False):
        #print("product && vendor match")
        success = True
    elif (vm) and (vendor_match and product == False and version_match == False):
        success = True


    if success:
        if loose:
            return "soft"
        else:
            return "exact"
    else:
        return "none"


def load_customer_data(file_path="/home/sjackso3/Downloads/sw.csv"):
    with open(file_path) as f:
        for line in f:
            cols = line.split(";")
            sw = software()
            sw.product = uniform_product(cols[0])
            sw.version = cols[1]
            sw.vendor = uniform_vendor(cols[2])
            sw_list.append(sw)


def load_mitre_cve(url='http://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2018.json.zip'):
    print(" Downloading zip file.....")
    r = requests.get(url)
    print("Processing zip.....")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    z.extractall()
    print(z.namelist())
    print("Reading file contents.....")
    f = z.open(z.namelist()[0])
    content = f.read()
    content_string = content.decode()
    type(content_string)
    #print("Content: "+content_string)

    print("Parsing JSON....")
    json_data = json.loads(content.decode())
    return json_data


# json_data - the json string with cve data.
# returns - array of objects
#
# TODO - define object to load into and load into those objects
def extract_mitre_json(json_data):
    highlight_missing = False
    highlight_complete = False
    total = 0.0
    missing = 0
    total_cve = len(json_data["CVE_Items"])
    start_time = time.time()
    for cve in json_data["CVE_Items"]:
        total += 1
        if total % 100 == 0:

            end_time = time.time()
            elapsed = end_time - start_time
            average_time_per = elapsed/total
            print(str(total) + "/" + str(total_cve) + " - " + str((total / total_cve) * 100) + "%   -  " +
                  str(elapsed)+" time/CVE: "+str(average_time_per))
        cve_number = cve["cve"]["CVE_data_meta"]["ID"]
        if len(cve["cve"]["affects"]["vendor"]["vendor_data"]) > 0:
            #static index 0 -- more than 1 vendor?
            vendor_name =cve["cve"]["affects"]["vendor"]["vendor_data"][0]["vendor_name"]
            #static index 0 - more than 1 product per vendor?
            product = cve["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]
            product_name =  product["product_data"][0]["product_name"]
            product_name = product_name.replace("_", " ")
            versions =  product["product_data"][0]["version"]["version_data"]
            description = cve["cve"]["description"]["description_data"][0]["value"]
            impact = cve["impact"]["baseMetricV3"]
            vector = impact["cvssV3"]["attackVector"]
            severity = impact["cvssV3"]["baseSeverity"]

            product_name = product_name.lower()
            #target = target.lower()
            description = description.lower()

            if highlight_missing is True and len(vendor_name) == 0 or len(product_name) == 0:
                print("Incomplete: " + cve_number +" :"+vendor_name+":"+product_name)
                missing += 1

            for v in versions:
                if highlight_complete is True:
                    print(vendor_name+" ; "+product_name+" ; " + v["version_value"] + " ; "+cve_number)
                for sw in sw_list:
                    search_result = find_sw_in_cve(sw, vendor=vendor_name, product=product_name, version=v["version_value"],
                             cve_desc=description, version_match=False)
                    if search_result != "none":
                        print(search_result+" MATCH!: "+cve_number+" @ "+str(sw) +"  ||  "+vendor_name+":"+product_name+"  = "+description)

        else:
            if highlight_missing is True:
                print("Incomplete: "+cve_number+":vendor data length :"+str(len(cve["cve"]["affects"]["vendor"]["vendor_data"])))
            #print(cve["cve"]["affects"]["vendor"]["vendor_data"])
            missing += 1
    print ("Incomplete data: "+str(missing)+"/"+str(total))


load_customer_data()
extract_mitre_json(load_mitre_cve())