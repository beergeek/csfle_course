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

func encryptManual(ce *mongo.ClientEncryption, d primitive.Binary, a string, b interface{}) (primitive.Binary, error) {
	var out primitive.Binary
	rawValueType, rawValueData, err := bson.MarshalValue(b)
	if err != nil {
		return primitive.Binary{}, err
	}

	rawValue := bson.RawValue{Type: rawValueType, Value: rawValueData}

	encryptionOpts := options.Encrypt().
		SetAlgorithm(a).
		SetKeyID(d)

	out, err = ce.Encrypt(context.TODO(), rawValue, encryptionOpts)
	if err != nil {
		return primitive.Binary{}, err
	}

	return out, nil
}

func encryptViaSchema(c *mongo.ClientEncryption, s []string, dek primitive.Binary, p bson.M, a string) (bson.M, error) {
	var err error
	if len(s) > 1 {
		p[s[0]], err = encryptViaSchema(c, s[1:], dek, p[s[0]].(bson.M), a)
		if err != nil {
			return bson.M{}, err
		}
		return p, nil
	}

	// if field absent return payload
	if p[s[0]] == nil {
		return p, nil
	}

	// Encrypt field value
	p[s[0]], err = encryptManual(c, dek, a, p[s[0]])
	if err != nil {
		return bson.M{}, err
	}
	return p, nil
}

func encryptData(c *mongo.ClientEncryption, s SchemaObject, dek primitive.Binary, p bson.M) (bson.M, error) {
	var err error

	for _, e := range s.deterministic {
		p, err = encryptViaSchema(c, e, dek, p, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic")
		if err != nil {
			return nil, err
		}
	}

	for _, e := range s.random {
		p, err = encryptViaSchema(c, e, dek, p, "AEAD_AES_256_CBC_HMAC_SHA_512-Random")
		if err != nil {
			return nil, err
		}
	}
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

	schema := SchemaObject{
		deterministic: [][]string{
			{"name", "firstname"},
			{"name", "lastname"},
		},
		random: [][]string{
			{"name", "othernames"},
			{"address", "streetAddress"},
			{"address", "suburbCounty"},
			{"dob"},
			{"phoneNumber"},
			{"salary"},
			{"taxIdentifier"},
		},
	}

	payload := bson.M{
		"_id": int32(2315),
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
	name := payload["name"].(bson.M)
	if name["othernames"] == nil {
		fmt.Println("Removing nil")
		delete(name, "othernames")
		payload["name"] = name
	}

	bsonPayload, err = encryptData(clientEncryption, schema, dek, payload)
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
