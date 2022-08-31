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

def encryptData(data, encryptedClient, alg, dek):
  try:
    return encryptedClient.encrypt(data, alg, dek), None
  except EncryptionError as e:
    return None, e

def decryptData(data, encryptedClient):
  try:
    return encryptedClient.decrypt(data), None
  except EncryptionError as e:
    return None, e

def nested_get(dic, keys):
  for key in keys:
    if key in dic:
      dic = dic[key]
    else:
      return
  return dic

def nested_set(dic, keys, value):
    for key in keys[:-1]:
      dic = dic[key]
    dic[keys[-1]] = value

def encryptPayload(en_client, schema, data, dek):
  for a in schema:
    for k in schema[a]:
      x = nested_get(data, k)
      if x:
        v, err = encryptData(x, en_client, a, dek)
        if err != None:
          return None, err
        nested_set(data, k, v)
  return data, None

def decryptPayload(en_client, schema, data):
  for a in schema:
    for k in schema[a]:
      x = nested_get(data, k)
      if x:
        v, err = decryptData(x, en_client)
        if err != None:
          return None, err
        nested_set(data, k, v)
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

  # This is a map to determine which fields to encrypt and with which algorithm
  schema_map = {
    Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic: [
      ["name", "firstname"],
      ["name", "lastname"]
    ],
    Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random: [
      ["name", "othernames"],
      ["address", "streetAddress"],
      ["address", "suburbCounty"],
      ["dob"],
      ["phoneNumber"],
      ["salary"],
      ["taxIdentifier"]
    ]
  }

  # Create our payload with encrypted values
  payload = {
    "_id": 2314, # employee ID
    "name": {
      "firstname": "Will",
      "lastname": "T",
      "othernames": None,
    },
    "address": {
      "streetAddress": "537 White Hills Rd",
      "suburbCounty": "Evandale",
      "zipPostcode": "7258",
      "stateProvince": "Tasmania",
      "country": "Oz"
    },
    "dob": datetime.datetime(1989, 1, 1),
    "phoneNumber": "+61 400 000 111",
    "salary": {
      "current": 99000.00,
      "startDate": datetime.datetime(2022, 6, 1),
      "history": [
        {
          "salary": 89000.00,
          "startDate": datetime.datetime(2021, 8, 1)
        }
      ]
    },
    "taxIdentifier": "103-443-923",
    "role": [
      "IC"
    ]
  }

  # remove `name.othernames` if None because wwe cannot encrypt none
  if payload["name"]["othernames"] == None:
    del(payload["name"]["othernames"])

  # encrypt parts of the payload that require encrypting
  payload, err = encryptPayload(client_encryption, schema_map, payload , data_key_id_1)
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
    result, err = decryptPayload(client_encryption, schema_map, encrypted_result)
    if err != None:
      print(f"Decrypt error: {err}")
      sys.exit(1)
    print(result)

if __name__ == "__main__":
  main()