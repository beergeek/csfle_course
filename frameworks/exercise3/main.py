try:
  import boto3
  import datetime
  import pymongo
  import random
  import sys
  from botocore.exceptions import ClientError
  from pymongo.errors import EncryptionError, DuplicateKeyError
  from bson.codec_options import CodecOptions
  from pymongo.encryption import Algorithm
  from bson.binary import STANDARD
  from pymongo.encryption import ClientEncryption
except ImportError as e:
  print(e)
  exit(1)

def mdb_client(db_data):
  try:
    if db_data['DB_SSL'] is True:
      client = pymongo.MongoClient(db_data['DB_CONNECTION_STRING'], serverSelectionTimeoutMS=db_data['DB_TIMEOUT'], ssl=True, ssl_ca_certs=db_data['DB_SSL_CA'])
    else:
      client = pymongo.MongoClient(db_data['DB_CONNECTION_STRING'], serverSelectionTimeoutMS=db_data['DB_TIMEOUT'])
    client.admin.command('hello')
    return client, None
  except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
    return None, "Cannot connect to database, please check settings in config file: %s" %e

def encryptPayload(<VARIABLES>):
  return data, None

def decryptPayload(<VARIABLES>):
  return data, None

def getAWSToken():
  try:
    sts_client = boto3.client('sts')
    # Call the assume_role method of the STSConnection object and pass the role
    # ARN and a role session name.
    # Obviously this should not be hardcoded
    assumed_role_object=sts_client.assume_role(
        RoleArn="arn:aws:iam::331472312345:role/ce-training-kms",
        RoleSessionName="applicationSession",
        DurationSeconds=3600
    )
    return assumed_role_object['Credentials'], None
  except ClientError as e:
    return None, e

def main():

  # Obviously this should not be hardcoded
  config_data = {
    "DB_CONNECTION_STRING": "mongodb+srv://mongoCryptoClient:<PASSWORD>@<CLUSTER_NAME>.bildu.mongodb.net",
    "DB_TIMEOUT": 5000,
    "DB_SSL": False
  }

  keyvault_namespace = f"__encryption.__keyVault"
  provider = "aws"
  assumed_role_object, err = getAWSToken()
  if err != None:
    print(f"AWS Token error: {err}")
    sys.exit(1)

  kms_provider = {
    provider: {
      "accessKeyId": assumed_role_object['AccessKeyId'],
      "secretAccessKey": assumed_role_object['SecretAccessKey'],
      "sessionToken": assumed_role_object['SessionToken']
    }
  }
  
  encrypted_db_name = "companyData"
  encrypted_coll_name = "employee"

  client, err = mdb_client(config_data)
  if err != None:
    print(f"MongoDB Client error: {err}")
    sys.exit(1)


  client_encryption = ClientEncryption(
    kms_provider,
    keyvault_namespace,
    client,
    CodecOptions(uuid_representation=STANDARD)
  )

  # retrieve the DEK UUID
  data_key_id_1 = client["__encryption"]["__keyVault"].find_one({"keyAltNames": "dataKey1"},{"_id": 1})['_id']

  # Create our payload with encrypted values
  # Complete this
  payload = { }

  # remove `name.othernames` if None because wwe cannot encrytp none
  # Complete this

  # encrypt parts of the payload that require encrypting
  # Complete this
  payload, err = encryptPayload(<VARIABLES>)
  if err != None:
    print(f"Encryption error: {err}")
    sys.exit(1)

  # insert our document
  try:
    result = client[encrypted_db_name][encrypted_coll_name].insert_one(payload)
    inserted_id = result.inserted_id
  except DuplicateKeyError as e:
    print("duplicate")
    inserted_id = payload["_id"]
  print(inserted_id)

  encrypted_result = client[encrypted_db_name][encrypted_coll_name].find_one({"_id": inserted_id})

  if encrypted_result:
    result, err = decryptPayload(<VARIABLES>)
    if err != None:
      print(f"Decrypt error: {err}")
      sys.exit(1)
    print(result)

if __name__ == "__main__":
  main()