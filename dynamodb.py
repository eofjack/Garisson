boto3
from boto3.dynamodb.conditions import Key, Attr

def test_dynamo_table():
    vendors = dynamodb.Table("vendor")
    response = vendors.get_item(Key={
        "id": "0"
    })
    vendor = response['Item']
    print(vendor)


#test_dynamo_table()


def search_for_vendor(vendor_name):
    vendors = dynamodb.Table("vendor")
    response = vendors.query(
        KeyConditionExpression=Key('username').eq('johndoe')
    )
    items = response['Items']
    print(items)



#init global dynamo resource
dynamodb = boto3.resource('dynamodb')
