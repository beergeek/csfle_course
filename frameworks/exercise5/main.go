package main

import (
	"C"
	"context"
	"errors"
	"fmt"
	"os"

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
	var durationSeconds int32 = 3200
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

func getDEK(c *mongo.Collection) (primitive.Binary, error) {
	var dekFindResult bson.M

	opts := options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}})
	err := c.FindOne(context.TODO(), bson.D{{Key: "keyAltNames", Value: "dataKey1"}}, opts).Decode(&dekFindResult)
	if err != nil {
		return primitive.Binary{}, err
	}
	if len(dekFindResult) == 0 {
		return primitive.Binary{}, errors.New("cannot find DEK")
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
		collection       = "employee"
		connectionString = "mongodb+srv://mongoCryptoClient:<PASSWORD>@<CLUSTER_NAME>.bildu.mongodb.net"
		db               = "companyData"
		dek              primitive.Binary
		encryptedClient  *mongo.Client
		exitCode         = 0
		findResult       bson.M
		key              int32
		keySpace         = "__encryption.__keyVault"
		kmsProvider      map[string]map[string]interface{}
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

	client, err = createClient(connectionString)
	if err != nil {
		fmt.Printf("MDB client error: %s\n", err)
		exitCode = 1
		return
	}

	coll := client.Database("__encryption").Collection("__keyVault")

	// Get the DEK UUID
	dek, err = getDEK(coll)
	if err != nil {
		fmt.Printf("DEK find error: %s\n", err)
		exitCode = 1
		return
	}

	// Our schema map
	// Complete this
	schemaMap = bson.M{}

	payload := bson.M{
		"_id": int32(2316),
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
	}

	// name.othernames can be `nil`, so let's test and remove if that condistion is true
	// Complete this
	payload = <FUNCTION>

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
		key = payload["_id"].(int32)
	} else if err != nil {
		fmt.Printf("Insert error: %s\n", err)
		exitCode = 1
		return
	} else {
		key = result.InsertedID.(int32)
	}
	fmt.Println(key)

	// retrieve our document
	err = coll.FindOne(context.TODO(), bson.M{"_id": key}).Decode(&findResult)
	if err != nil {
		fmt.Printf("find error: %s\n", err)
		exitCode = 1
		return
	}
	fmt.Println(findResult)

	exitCode = 0
}
