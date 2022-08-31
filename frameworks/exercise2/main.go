package main

import (
	"C"
	"context"
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

type SchemaObject struct {
	deterministic [][]string
	random        [][]string
}

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

func createManualEncryptionClient(c *mongo.Client, kp map[string]map[string]interface{}, kns string) (*mongo.ClientEncryption, error) {
	o := options.ClientEncryption().SetKeyVaultNamespace(kns).SetKmsProviders(kp)
	client, err := mongo.NewClientEncryption(c, o)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Manually encrypt a single variable
// Complete this
func encryptManual(<VARIABLES>) {
	var out primitive.Binary

	// Create code here

	return out, nil
}

// Encrypt all the data that requires encrypting within the payload
// Complete this
func encryptData(<VARIABLES>) (bson.M, error) {
	var err error
	return p, nil
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
		kmsProvider      map[string]map[string]interface{}
		keySpace         = "__encryption.__keyVault"
		connectionString = "mongodb+srv://mongoCryptoClient:<PASSWORD>@<CLUSTER_NAME>.bildu.mongodb.net"
		clientEncryption *mongo.ClientEncryption
		client           *mongo.Client
		exitCode         = 0
		result           *mongo.InsertOneResult
		dekFindResult    bson.M
		bsonPayload      bson.M
		dek              primitive.Binary
		key              int32
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

	clientEncryption, err = createManualEncryptionClient(client, kmsProvider, keySpace)
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	// Our payload
	// Complete this
	payload := bson.M{}

	// name.othernames can be `nil`, so let's test and remove if that condistion is true
	// Complete this
	payload = <FUNCTION>

	// Encryption our payload where required
	// Complete this
	bsonPayload, err = encryptData(<VARIABLES>)
	if err != nil {
		fmt.Printf("Encrypt failure: %s", err)
		exitCode = 1
		return
	}

	coll = client.Database("companyData").Collection("employee")

	result, err = coll.InsertOne(context.TODO(), bsonPayload)
	if mongo.IsDuplicateKeyError(err) {
		fmt.Println("Duplicate key, continuing")
		key = payload["_id"].(int32)
	} else if err != nil {
		fmt.Printf("Insert error: %s\n", err)
		exitCode = 1
		return
	} else {
		fmt.Print(result.InsertedID)
		key = result.InsertedID.(int32)
	}
	fmt.Println(key)

	exitCode = 0
}
