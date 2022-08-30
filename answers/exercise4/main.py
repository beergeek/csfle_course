try:
  import boto3
  import datetime
  import pymongo
  import sys
  from botocore.exceptions import ClientError
  from pymongo.errors import EncryptionError, DuplicateKeyError
  from pymongo.encryption_options import AutoEncryptionOpts
  from bson.binary import UUID_SUBTYPE, Binary
except ImportError as e:
  print(e)
  exit(1)

def mdb_client(db_data, auto_encryption_opts=None):
  try:
    if db_data['DB_SSL'] is True:
      client = pymongo.MongoClient(db_data['DB_CONNECTION_STRING'], serverSelectionTimeoutMS=db_data['DB_TIMEOUT'], ssl=True, ssl_ca_certs=db_data['DB_SSL_CA'], auto_encryption_opts=auto_encryption_opts)
    else:
      client = pymongo.MongoClient(db_data['DB_CONNECTION_STRING'], serverSelectionTimeoutMS=db_data['DB_TIMEOUT'], auto_encryption_opts=auto_encryption_opts)
    client.admin.command('hello')
    return client, None
  except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
    return None, f"Cannot connect to database, please check settings in config file: {e}"

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

  # retrieve the DEK UUID
  data_key_id_1 = client["__encryption"]["__keyVault"].find_one({"keyAltNames": "dataKey1"},{"_id": 1})['_id']
  # close the client as we no longer require
  client.close()

  # This is a map to determine which fields to encrypt and with which algorithm
  schema_map = {
		f"{encrypted_db_name}.{encrypted_coll_name}": {
			"bsonType": "object",
			"encryptMetadata": {
				"keyId": [Binary(data_key_id_1, UUID_SUBTYPE)],
				"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
			},
			"properties": {
				"name": {
					"bsonType": "object",
					"properties": {
						"firstname": {
							"encrypt": {
								"bsonType":  "string",
								"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
							}
						},
						"lastname": {
							"encrypt": {
								"bsonType":  "string",
								"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
							}
						},
						"othernames": {
							"encrypt": {
								"bsonType": "string"
							}
						}
					}
				},
				"address": {
					"bsonType": "object",
					"properties": {
						"streetAddress": {
							"encrypt": {
								"bsonType": "string"
							}
						},
						"suburbCounty": {
							"encrypt": {
								"bsonType": "string"
							}
						}
					}
				},
				"phoneNumber": {
					"encrypt": {
						"bsonType": "string"
					}
				},
				"salary": {
					"encrypt": {
						"bsonType": "object"
					}
				},
				"taxIdentifier": {
					"encrypt": {
						"bsonType": "string"
					}
				}
			}
		}
	}

  # Create our payload with encrypted values from our frontend
  payload = {
    "_id": 2319, # employee ID
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

  # remove `name.othernames` if None because wwe cannot encrytp none
  if payload["name"]["othernames"] == None:
    del(payload["name"]["othernames"])

  auto_encryption = AutoEncryptionOpts(
    kms_provider,
    keyvault_namespace,
    schema_map = None #schema_map
  )

  # create our secure client
  secure_client, err = mdb_client(config_data, auto_encryption_opts=auto_encryption)
  if err != None:
    print(err)
    sys.exit(1)
  encrypted_db = secure_client[encrypted_db_name]
  
  try:
    result = encrypted_db[encrypted_coll_name].insert_one(payload)
    print(result.inserted_id)
  except EncryptionError as e:
    print(e)
    sys.exit(1)
  except DuplicateKeyError as e:
    print("duplicate")
    print(payload["_id"])

if __name__ == "__main__":
  main()