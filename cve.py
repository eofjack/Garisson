import requests, zipfile, io, json, boto3
from boto3.dynamodb.conditions import Key, Attr


host = "wpt23243"
target = "cisco"
#init global dynamo resource
dynamodb = boto3.resource('dynamodb')

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
    highlight_missing = True
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
                if highlight_missing is False:
                    print(vendor_name+" ; "+product_name+" ; " + v["version_value"] + " ; "+cve_number)

        else:
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


extract_mitre_json(load_mitre_cve())

test_dynamo_table()


def search_for_vendor(vendor_name):
    vendors = dynamodb.Table("vendor")
    response = vendors.query(
        KeyConditionExpression=Key('username').eq('johndoe')
    )
    items = response['Items']
    print(items)