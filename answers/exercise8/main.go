package main

import (
	"C"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func getAWSToken() (*sts.AssumeRoleOutput, error) {
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithSharedConfigProfile("Services.User-331472312345"),
	)
	if err != nil {
		return nil, err
	}

	// Create a STS client
	svc := sts.NewFromConfig(cfg)

	roleToAssumeArn := "arn:aws:iam::331472312345:role/ce-training-kms"
	sessionName := "test_session"
	var durationSeconds int32 = 3600
	result, err := svc.AssumeRole(context.TODO(), &sts.AssumeRoleInput{
		RoleArn:         &roleToAssumeArn,
		RoleSessionName: &sessionName,
		DurationSeconds: &durationSeconds,
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

func createClient(c string) (*mongo.Client, error) {
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(c))

	if err != nil {
		return nil, err
	}

	return client, nil
}

func createEncryptedClient(c string, ns string, kms map[string]map[string]interface{}, s bson.M) (*mongo.Client, error) {
	autoEncryptionOpts := options.AutoEncryption().
		SetKeyVaultNamespace(ns).
		SetKmsProviders(kms).
		SetSchemaMap(s)

	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(c).SetAutoEncryptionOptions(autoEncryptionOpts))

	if err != nil {
		return nil, err
	}

	return client, nil
}

func createClientEncryptionInstance(c *mongo.Client, kp map[string]map[string]interface{}, kns string) (*mongo.ClientEncryption, error) {
	o := options.ClientEncryption().SetKeyVaultNamespace(kns).SetKmsProviders(kp)
	client, err := mongo.NewClientEncryption(c, o)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func createDEK(c *mongo.Client, kn string, kp map[string]map[string]interface{}, kns string, cmk map[string]interface{}, altName string) (primitive.Binary, error) {
	var (
		ce  *mongo.ClientEncryption
		dek primitive.Binary
		err error
	)

	ce, err = createClientEncryptionInstance(c, kp, kns)
	if err != nil {
		return primitive.Binary{}, err
	}

	ceOpts := options.DataKey().
		SetMasterKey(cmk).
		SetKeyAltNames([]string{altName})
	dek, err = ce.CreateDataKey(context.TODO(), kn, ceOpts)
	if err != nil {
		return primitive.Binary{}, err
	}

	return dek, nil
}

func getEmployeeDEK(c *mongo.Client, kn string, kp map[string]map[string]interface{}, kns string, cmk map[string]interface{}, altName string, kdb string, kcoll string) (primitive.Binary, error) {
	var (
		err error
		dek primitive.Binary
	)

	dek, err = getDEK(c.Database(kdb).Collection(kcoll), altName)
	if err != nil {
		if err != mongo.ErrNoDocuments {
			return primitive.Binary{}, err
		}
		// If not DEK then create one
		dek, err = createDEK(c, kn, kp, kns, cmk, altName)
		if err != nil {
			return primitive.Binary{}, err
		}
	}

	return dek, nil
}

func trashDEK(c *mongo.Client, kp map[string]map[string]interface{}, kns string, keyID primitive.Binary) error {
	var (
		ce        *mongo.ClientEncryption
		delResult *mongo.DeleteResult
		err       error
	)

	ce, err = createClientEncryptionInstance(c, kp, kns)
	if err != nil {
		return err
	}

	delResult, err = ce.DeleteKey(context.TODO(), keyID)
	if err != nil {
		return err
	}
	if delResult.DeletedCount == 0 {
		return errors.New("no DEK deleted")
	}

	return nil
}

func getDEK(c *mongo.Collection, altName string) (primitive.Binary, error) {
	var dekFindResult bson.M

	opts := options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}})
	err := c.FindOne(context.TODO(), bson.M{"keyAltNames": altName}, opts).Decode(&dekFindResult)
	if err != nil {
		return primitive.Binary{}, err
	}
	if len(dekFindResult) == 0 {
		return primitive.Binary{}, nil
	}
	b, ok := dekFindResult["_id"].(primitive.Binary)
	if !ok {
		return primitive.Binary{}, errors.New("the DEK conversion error")
	}
	return b, nil
}

func main() {
	var (
		client           *mongo.Client
		cmk              map[string]interface{}
		collection       = "employee"
		connectionString = "mongodb+srv://mongoCryptoClient:<PASSWORD>@<CLUSTER_NAME>.bildu.mongodb.net"
		db               = "companyData"
		dek              primitive.Binary
		employeeDEK      primitive.Binary
		encryptedClient  *mongo.Client
		exitCode         = 0
		findResult       bson.M
		key              int32
		keyDB            = "__encryption"
		keyCollection    = "__keyVault"
		keySpace         = keyDB + "." + keyCollection
		kmsProvider      map[string]map[string]interface{}
		kmsName          = "aws"
		result           *mongo.InsertOneResult
		schemaMap        map[string]interface{}
	)

	defer func() {
		os.Exit(exitCode)
	}()

	role, err := getAWSToken()
	if err != nil {
		fmt.Printf("Token error: %s\n", err)
		exitCode = 1
		return
	}

	kmsProvider = map[string]map[string]interface{}{
		"aws": {
			"accessKeyId":     &role.Credentials.AccessKeyId,
			"secretAccessKey": &role.Credentials.SecretAccessKey,
			"sessionToken":    &role.Credentials.SessionToken,
		},
	}

	cmk = map[string]interface{}{
		"region": "ap-southeast-2",
		"key":    "6a822d91-15b0-4d8f-b1bb-2f180b9e1d2f",
	}

	client, err = createClient(connectionString)
	if err != nil {
		fmt.Printf("MDB client error: %s\n", err)
		exitCode = 1
		return
	}

	rand.Seed(time.Now().UnixNano())
	id := int32(rand.Intn(100000))

	employeeDEK, err = getEmployeeDEK(client, kmsName, kmsProvider, keySpace, cmk, strconv.FormatInt(int64(id), 10), keyDB, keyCollection)
	if err != nil {
		fmt.Printf("Cannot get employee DEK: %s\n", err)
		exitCode = 1
		return
	}

	coll := client.Database("__encryption").Collection("__keyVault")

	// Get the DEK UUID
	dek, err = getDEK(coll, "dataKey1")
	if err != nil {
		fmt.Printf("DEK find error: %s\n", err)
		exitCode = 1
		return
	}

	schemaMap = bson.M{
		db + "." + collection: bson.M{
			"bsonType": "object",
			"encryptMetadata": bson.M{
				"keyId":     "/dekAltName",
				"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random",
			},
			"properties": bson.M{
				"name": bson.M{
					"bsonType": "object",
					"properties": bson.M{
						"firstname": bson.M{
							"encrypt": bson.M{
								"bsonType":  "string",
								"keyId":     bson.A{dek},
								"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
							},
						},
						"lastname": bson.M{
							"encrypt": bson.M{
								"bsonType":  "string",
								"keyId":     bson.A{dek},
								"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
							},
						},
						"othernames": bson.M{
							"encrypt": bson.M{
								"bsonType": "string",
							},
						},
					},
				},
				"address": bson.M{
					"bsonType": "object",
					"properties": bson.M{
						"streetAddress": bson.M{
							"encrypt": bson.M{
								"bsonType": "string",
							},
						},
						"suburbCounty": bson.M{
							"encrypt": bson.M{
								"bsonType": "string",
							},
						},
					},
				},
				"phoneNumber": bson.M{
					"encrypt": bson.M{
						"bsonType": "string",
					},
				},
				"salary": bson.M{
					"encrypt": bson.M{
						"bsonType": "object",
					},
				},
				"taxIdentifier": bson.M{
					"encrypt": bson.M{
						"bsonType": "string",
					},
				},
			},
		},
	}

	payload := bson.M{
		"_id": id,
		"name": bson.M{
			"firstname":  "Will",
			"lastname":   "T",
			"othernames": nil,
		},
		"address": bson.M{
			"streetAddress": "537 White Hills Rd",
			"suburbCounty":  "Evandale",
			"zipPostcode":   "7258",
			"stateProvince": "Tasmania",
			"country":       "Oz",
		},
		"dob":         time.Date(1989, 1, 1, 0, 0, 0, 0, time.Local),
		"phoneNumber": "+61 400 000 111",
		"salary": bson.M{
			"current":   99000.00,
			"startDate": time.Date(2022, 6, 1, 0, 0, 0, 0, time.Local),
			"history": bson.M{
				"salary":    89000.00,
				"startDate": time.Date(2021, 8, 1, 0, 0, 0, 0, time.Local),
			},
		},
		"taxIdentifier": "103-443-923",
		"role":          []string{"IC"},
		"dekAltName":    strconv.FormatInt(int64(id), 10),
	}

	// name.othernames can be `nil`, so let's test and remove if that condistion is true
	name := payload["name"].(bson.M)
	if name["othernames"] == nil {
		fmt.Println("Removing nil")
		delete(name, "othernames")
		payload["name"] = name
	}

	encryptedClient, err = createEncryptedClient(connectionString, keySpace, kmsProvider, schemaMap)
	if err != nil {
		fmt.Printf("MDB encrypted client error: %s\n", err)
		exitCode = 1
		return
	}

	coll = encryptedClient.Database(db).Collection(collection)

	result, err = coll.InsertOne(context.TODO(), payload)
	if mongo.IsDuplicateKeyError(err) {
		fmt.Println("Duplicate key, continuing")
		// this is just to handle the duplicate key for this exercise and should not be done in real world scenarios
		key = payload["_id"].(int32)
	} else if err != nil {
		fmt.Printf("Insert error: %s\n", err)
		exitCode = 1
		return
	} else {
		key = result.InsertedID.(int32)
	}

	// retrieve our document in unencrypted format
	err = client.Database(db).Collection(collection).FindOne(context.TODO(), bson.M{"_id": key}).Decode(&findResult)
	if err != nil {
		fmt.Printf("find error: %s\n", err)
		exitCode = 1
		return
	}
	fmt.Println(findResult)

	// retrieve our document in encrypted format
	err = coll.FindOne(context.TODO(), bson.M{"_id": key}).Decode(&findResult)
	if err != nil {
		fmt.Printf("find error: %s\n", err)
		exitCode = 1
		return
	}
	fmt.Println(findResult)

	err = trashDEK(client, kmsProvider, keySpace, employeeDEK)
	if err != nil {
		fmt.Printf("DEK deletion error: %s", err)
	}
	time.Sleep(61 * time.Second)

	// retrieve our document in encrypted format
	err = coll.FindOne(context.TODO(), bson.M{"_id": key}).Decode(&findResult)
	if err != nil {
		match, _ := regexp.MatchString("not all keys requested were satisfied", err.Error())
		if match {
			fmt.Println("DEK missing or deleted")
			exitCode = 0
			return
		}
		fmt.Printf("find error: %s\n", err)
		exitCode = 1
		return
	}
	fmt.Println(findResult)

	exitCode = 0
}
