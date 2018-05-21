import requests, zipfile, io, json, boto3
from boto3.dynamodb.conditions import Key, Attr


class software:
    vendor = ""
    product = ""
    version = ""
    cve = []

    def __str__(self):
        return self.vendor+" - "+self.product+" - "+self.version

#init global dynamo resource
dynamodb = boto3.resource('dynamodb')

sw_list = []

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
        if vendor in sw.vendor or sw.vendor in vendor:
            vm = True
            loose = True
    if product_match and (len(sw.product) > 0 and len(product) > 0):
        if product == sw.product:
            pm = True
        if product in sw.product or sw.product in product:
            pm = True
            loose = True
    if version_match and (len(sw.version) > 0 and len(version) > 0):
        if version == sw.version:
            vem = True
        if version in sw.version or sw.version in version:
            vem = True
            loose = True


    success = False
    if (vem and pm and vm) and (product_match and vendor_match and version_match):
        success = True
    elif ( pm and vm) and (product_match and vendor_match):
        success = True
    elif (vm) and (vendor_match):
        success = True


    if success:
        if loose:
            return "soft"
        else:
            return "exact"
    else:
        return "none"

def load_customer_data(file_path="C:\\Users\\SSJ\\Downloads\\sw.csv"):
    with open(file_path) as f:
        for line in f:
            cols = line.split(";")
            sw = software()
            sw.product = cols[0]
            sw.version = cols[1]
            sw.vendor = cols[2]
            sw_list.append(sw)


def load_mitre_cve(url='https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2018.json.zip'):
    print(" Downloading zip file.....")
    r = requests.get(url)
    print("Processing zip.....")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    z.extractall()
    print(z.namelist())
    print("Reading file contents.....")
    f = z.open(z.namelist()[0])
    content = f.read()
    print("Parsing JSON....")
    json_data = json.loads(content)
    return json_data


# json_data - the json string with cve data.
# returns - array of objects
#
# TODO - define object to load into and load into those objects
def extract_mitre_json(json_data):
    highlight_missing = False
    highlight_complete = False
    total = 0
    missing = 0

    for cve in json_data["CVE_Items"]:
        total += 1
        cve_number = cve["cve"]["CVE_data_meta"]["ID"]
        if len(cve["cve"]["affects"]["vendor"]["vendor_data"])>0:
            #static index 0 -- more than 1 vendor?
            vendor_name =cve["cve"]["affects"]["vendor"]["vendor_data"][0]["vendor_name"]
            #static index 0 - more than 1 product per vendor?
            product = cve["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]
            product_name =  product["product_data"][0]["product_name"]
            versions =  product["product_data"][0]["version"]["version_data"]
            description = cve["cve"]["description"]["description_data"][0]["value"]
            impact = cve["impact"]["baseMetricV3"]
            vector = impact["cvssV3"]["attackVector"]
            severity = impact["cvssV3"]["baseSeverity"]

            product_name = product_name.lower()
           # target = target.lower()
            description = description.lower()

            if highlight_missing is True and len(vendor_name) == 0 or len(product_name) == 0:
                print("Incomplete: " + cve_number +" :"+vendor_name+":"+product_name)
                missing += 1

            for v in versions:
                if highlight_complete is True:
                    print(vendor_name+" ; "+product_name+" ; " + v["version_value"] + " ; "+cve_number)
                for sw in sw_list:
                    if match_sw(sw, vendor=vendor_name, product=product_name.replace("_"," "), version=v["version_value"], version_match=False) != "none":
                        print("MATCH!: "+cve_number+" @ "+str(sw))

        else:
            if highlight_missing is False:
                print("Incomplete: "+cve_number+":vendor data length :"+str(len(cve["cve"]["affects"]["vendor"]["vendor_data"])))
            #print(cve["cve"]["affects"]["vendor"]["vendor_data"])
            missing += 1
    print ("Incomplete data: "+str(missing)+"/"+str(total))


def test_dynamo_table():
    vendors = dynamodb.Table("vendor")
    response = vendors.get_item(Key={
        "id": "0"
    })
    vendor = response['Item']
    print(vendor)

load_customer_data()
extract_mitre_json(load_mitre_cve())

#test_dynamo_table()


def search_for_vendor(vendor_name):
    vendors = dynamodb.Table("vendor")
    response = vendors.query(
        KeyConditionExpression=Key('username').eq('johndoe')
    )
    items = response['Items']
    print(items)