try:
  import boto3
  import datetime
  import names
  import pymongo
  import random
  import sys
  from botocore.exceptions import ClientError
  from pymongo.errors import DuplicateKeyError, EncryptionError
  from bson.codec_options import CodecOptions
  from random_address import real_random_address
  from pymongo.encryption_options import AutoEncryptionOpts
  from bson.binary import STANDARD, Binary, UUID_SUBTYPE
  from pymongo.encryption import ClientEncryption
  from pprint import pprint
except ImportError as e:
  print(e)
  exit(1)

def mdb_client(db_data, auto_encryption_opts=None):
  try:
    if db_data['DB_SSL'] is True:
      if db_data['DB_SSL_PEM'] is not None:
        client = pymongo.MongoClient(db_data['DB_ONNECTION_STRING'], serverSelectionTimeoutMS=db_data['DB_TIMEOUT'], ssl=True, ssl_certfile=db_data['DB_SSL_PEM'], ssl_ca_certs=db_data['DB_SSL_CA'], auto_encryption_opts=auto_encryption_opts)
      else:
        client = pymongo.MongoClient(db_data['DB_CONNECTION_STRING'], serverSelectionTimeoutMS=db_data['DB_TIMEOUT'], ssl=True, ssl_ca_certs=db_data['DB_SSL_CA'], auto_encryption_opts=auto_encryption_opts)
    else:
      client = pymongo.MongoClient(db_data['DB_CONNECTION_STRING'], serverSelectionTimeoutMS=db_data['DB_TIMEOUT'], auto_encryption_opts=auto_encryption_opts)
    if auto_encryption_opts == None:
      result = client.admin.command('hello')
    return client, None
  except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
    return None, f"Cannot connect to database, please check settings in config file: {e}"

def getAWSToken():
  try:
    sts_client = boto3.client('sts')
    # Call the assume_role method of the STSConnection object and pass the role
    # ARN and a role session name.
    assumed_role_object=sts_client.assume_role(
        RoleArn="arn:aws:iam::331472312345:role/ce-training-kms",
        RoleSessionName="applicationSession",
        DurationSeconds=3600
    )
    return assumed_role_object['Credentials']
  except ClientError as e:
    return None, f"AWS Token error: {e}"

def gen_phone():
  n = '0000000000'
  while '9' in n[3:6] or n[3:6]=='000' or n[6]==n[7]==n[8]==n[9]:
    n = str(random.randint(10**9, 10**10-1))
  return n[:3] + '-' + n[3:6] + '-' + n[6:]

def rand_dates(points, years):
  dates = []
  for p in range(points):
    weeks = random.randint(1, years * 52)
    dates.append(datetime.datetime.now() - datetime.timedelta(weeks=weeks))
  dates.sort(reverse=True)
  return dates

def rand_salary(points):
  salaries = []
  for p in range(points):
    salaries.append(random.randint(10**4*8, 10**5*3))
  salaries.sort(reverse=True)
  return salaries

def get_history(dates, salaries):
  history = []
  for i in range(1, len(dates)):
    history.append({"salary": salaries[i], "startDate": dates[i]})
  return history

def get_roles():
  role_list = ["IC","Manager", "HR", "COO", "CEO", "CTO", "CISO"]
  roles = random.sample(role_list, random.randint(1, 3))
  return roles

def get_dob(years):
  dob = datetime.datetime.now() - datetime.timedelta(weeks=(52*18+years+(random.randint(0, 5200))))
  return dob

def gen_employee():
  # generate some data
  employment_history = random.randint(1, 10)
  salary_points = random.randint(1, employment_history)
  dates = rand_dates(salary_points, employment_history)
  salaries = rand_salary(salary_points)
  salary_history = get_history(dates, salaries)
  address = real_random_address()
  id = random.randint(10**12, 10**13 - 1)
  employee = {
    "_id": id,
    "name": {
      "firstname": names.get_first_name(),
      "lastname": names.get_last_name(),
      "othernames": random.choice([names.get_first_name(), None]),
    },
    "address": {
      "streetAddress": address['address1'],
      "suburbCounty": address['city'],
      "stateProvince": address['state'],
      "zipPostcode": address['postalCode'],
      "country": "USA",
    },
    "phoneNumber": gen_phone(),
    "dob": get_dob(employment_history),
    "taxIdentifier": str(random.randint(10**12, 10**13 - 1)),
    "salary": {
      "current": salaries[0],
      "startDate": dates[0],
      "history": salary_history
    },
    "role": get_roles(),
    "dekAltName": str(id),
  }
  return employee

def get_employee_key(client, kms, p, ns, id):
  employee_key_id = client["__encryption"]["__keyVault"].find_one({"keyAltNames": id},{"_id": 1})
  if employee_key_id == None:
    try:
      client_encryption = ClientEncryption(
        kms,
        ns,
        client,
        CodecOptions(uuid_representation=STANDARD)
      )

      master_key = {"region": "ap-southeast-2", "key": "6a822d91-15b0-4d8f-b1bb-2f180b9e1d2f"}
      employee_key_id = client_encryption.create_data_key(kms_provider=p, master_key=master_key, key_alt_names=[str(id)])
      client_encryption.close()
    except EncryptionError as e:
      return None, f"ClientEncryption error: {e}"
  else:
    employee_key_id = employee_key_id["_id"]
  return employee_key_id, None

def trash_employee_key(client, kms, ns, id):
  try:
    client_encryption = ClientEncryption(
      kms,
      ns,
      client,
      CodecOptions(uuid_representation=STANDARD)
    )
    employee_key_id = client_encryption.delete_key(id)
    if employee_key_id.deleted_count == 1:
      return True, None
    else:
      return None, "Failed to delete DEK"
    client_encryption.close()
  except EncryptionError as e:
    return None, f"ClientEncryption error: {e}"


def main():

  config_data = {
    "DB_CONNECTION_STRING": "mongodb+srv://mongoCryptoClient:<PASSWORD>@<CLUSTER_NAME>.bildu.mongodb.net",
    "DB_TIMEOUT": 5000,
    "DB_SSL_PEM": False,
    "DB_SSL": False
  }

  employee = gen_employee()

  client, err = mdb_client(config_data)
  if err != None:
    print(err)
    sys.exit(1)

  namespace = f"__encryption.__keyVault"
  provider = "aws"
  assumed_role_object = getAWSToken()

  kms_provider = {
    provider: {
      "accessKeyId": assumed_role_object['AccessKeyId'],
      "secretAccessKey": assumed_role_object['SecretAccessKey'],
      "sessionToken": assumed_role_object['SessionToken']
    }
  }

  # Check if DEK exists, if it does not create a ClientEncryption instance and then create the key
  data_key_id = client["__encryption"]["__keyVault"].find_one({"keyAltNames": "dataKey1"},{"_id": 1})
  if data_key_id:
    data_key_id = data_key_id["_id"]
  else:
    print("No dek found")
    sys.exit(1)
  employee_key_id, err = get_employee_key(client, kms_provider, provider, namespace, employee["dekAltName"])
  if err != None:
    print(err)
    sys.exit(1)
  
  print(f"Employee DEK: {employee_key_id}")

  encrypted_db_name = "companyData"
  encrypted_coll_name = "employee"
  schema_map =  {
		f"{encrypted_db_name}.{encrypted_coll_name}": {
			"bsonType": "object",
			"encryptMetadata": {
				"keyId": "/dekAltName",
				"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
			},
			"properties": {
				"name": {
					"bsonType": "object",
					"properties": {
						"firstname": {
							"encrypt": {
								"bsonType":  "string",
                "keyId": [Binary(data_key_id, UUID_SUBTYPE)],
								"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
							}
						},
						"lastname": {
							"encrypt": {
								"bsonType":  "string",
                "keyId": [Binary(data_key_id, UUID_SUBTYPE)],
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
				"dob": {
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
  
  auto_encryption = AutoEncryptionOpts(
    kms_provider,
    namespace,
    schema_map = schema_map
  )

  secure_client, err = mdb_client(config_data, auto_encryption_opts=auto_encryption)
  if err != None:
    print(err)
    sys.exit(1)
  encrypted_db = secure_client[encrypted_db_name]

  # remove `name.othernames` if None because wwe cannot encrypt none
  if employee["name"]["othernames"] == None:
    del(employee["name"]["othernames"])
  
  try:
    result = encrypted_db[encrypted_coll_name].insert_one(employee)
    inserted_id = result.inserted_id
  except EncryptionError as e:
    print(f"Encryption error: {e}")
    sys.exit(1)
  except DuplicateKeyError as e:
    print("duplicate")
    inserted_id = employee["_id"]
  
  encrypted_result = client[encrypted_db_name][encrypted_coll_name].find_one({"_id": inserted_id},{"dekAltName": 0})

  pprint(encrypted_result)
  
  decrypted_result = encrypted_db[encrypted_coll_name].find_one({"_id": inserted_id},{"dekAltName": 0})

  pprint(decrypted_result)

  trash_employee_key(client, kms_provider, namespace, employee_key_id)


if __name__ == "__main__":
  main()