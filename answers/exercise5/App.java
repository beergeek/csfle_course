package exercise5;

import static com.mongodb.client.model.Filters.eq;

import com.mongodb.AutoEncryptionSettings;
import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoNamespace;
import com.mongodb.ServerApi;
import com.mongodb.ServerApiVersion;
import com.mongodb.WriteError;
import com.mongodb.reactivestreams.client.MongoClient;
import com.mongodb.reactivestreams.client.MongoClients;
import com.mongodb.reactivestreams.client.MongoCollection;
import com.mongodb.reactivestreams.client.MongoDatabase;
import com.mongodb.client.model.Projections;
import com.mongodb.client.result.InsertOneResult;

import org.bson.BsonDocument;
import org.bson.BsonDocumentReader;
import org.bson.Document;
import org.bson.UuidRepresentation;
import org.bson.codecs.DecoderContext;
import org.bson.codecs.DocumentCodec;

import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.mongodb.MongoInterruptedException;
import com.mongodb.MongoTimeoutException;
import com.mongodb.MongoWriteException;

import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class App {
    static Logger logger = LoggerFactory.getLogger("AsyncApp");
    
    public static Document toDoc(BsonDocument bsonDocument) {
        DocumentCodec codec = new DocumentCodec();
        DecoderContext decoderContext = DecoderContext.builder().build();
        Document doc = codec.decode(new BsonDocumentReader(bsonDocument), decoderContext);
        return doc;
    }
        
    public App() {
    }

    /**
     * Get a configured MongoClient instance.
     * 
     * Note that certificates are set through the JVM trust and key stores.
     * 
     * @param connectionString
     * @param dbTimeout
     * @param useSSL
     * @param autoEncryptionSettings
     * @return
     */
    public MongoClient getMdbClient(String connectionString, int dbTimeout, boolean useSSL, AutoEncryptionSettings autoEncryptionSettings) {

        ConnectionString mdbConnectionString = new ConnectionString(connectionString);
        MongoClientSettings.Builder settingsBuilder = MongoClientSettings.builder()
                .applyConnectionString(mdbConnectionString)
                .serverApi(ServerApi.builder()
                    .version(ServerApiVersion.V1)
                    .build())
                .uuidRepresentation(UuidRepresentation.STANDARD);
        if (autoEncryptionSettings != null) {
            settingsBuilder = settingsBuilder.autoEncryptionSettings(autoEncryptionSettings);
        }

        // NB - using the builder with useSSL=false leads to problems
        if (useSSL) {
            settingsBuilder = settingsBuilder.applyToSslSettings(builder -> builder.enabled(useSSL));
        }

        MongoClientSettings settings = settingsBuilder.build();
        MongoClient mongoClient = MongoClients.create(settings);
        return mongoClient;
    } 

    public MongoClient getMdbClient(String connectionString, int dbTimeout, boolean useSSL) {
        return this.getMdbClient(connectionString, dbTimeout, useSSL, null);
    }

    public UUID getDekUUID(MongoClient client, MongoNamespace keyvaultNamespace) {
        System.out.println(client.getClusterDescription());
        MongoDatabase keyvaultDatabase = client.getDatabase(keyvaultNamespace.getDatabaseName());
        System.out.println(keyvaultDatabase.listCollectionNames());
        MongoCollection<Document> keyvaultCollection = keyvaultDatabase.getCollection(keyvaultNamespace.getCollectionName());
        ObservableSubscriber<Document> docSubscriber = new OperationSubscriber<Document>();
        keyvaultCollection
            .find(eq("keyAltNames", "dataKey1"))
            .projection(Projections.fields(Projections.include("_id")))
            .subscribe(docSubscriber);
        Document dataKeyDoc = docSubscriber.first();

        UUID dataKey1 = dataKeyDoc.get("_id", UUID.class);
        return dataKey1;
    }

    public Document getPayload() {

        String rawJson = """
{
  "_id": 2317,
  "name": {
    "first_name": "Will",
    "last_name": "T",
    "othernames": null,
  },
  "address": {
    "streetAddress": "537 White Hills Rd",
    "suburbCounty": "Evandale",
    "zipPostcode": "7258",
    "stateProvince": "Tasmania",
    "country": "Oz"
  },
  "dob": ISODate("1989-01-01T00:00:00.000Z"),
  "phoneNumber": "+61 400 000 111",
  "salary": {
    "current": 99000.00,
    "startDate": ISODate("2022-06-01T00:00:00.000Z"),
    "history": [
      {
        "salary": 89000.00,
        "startDate": ISODate("2021-08-11T00:00:00.000Z")
      }
    ]
  },
  "taxIdentifier": "103-443-923",
  "role": [
    "IC"
  ]
}
                """;
        BsonDocument bsonDoc = BsonDocument.parse(rawJson);
        return toDoc(bsonDoc);
    }

    public Credentials getAWSToken() {
        StsClientBuilder builder = StsClient.builder();
        StsClient stsClient = builder.build();
        String roleArn = "arn:aws:iam::331472312345:role/ce-training-kms";
        String roleSessionName = "applicationSession";
        int durnSeconds = 3600;
        AssumeRoleRequest roleRequest = AssumeRoleRequest.builder()
            .roleArn(roleArn)
            .roleSessionName(roleSessionName)
            .durationSeconds(durnSeconds)
            .build();

        AssumeRoleResponse assumedRole = stsClient.assumeRole(roleRequest);
        Credentials credentials = assumedRole.credentials();
        return credentials;
    }
    
    public BsonDocument getSchemaDocument(UUID dekUuid) {
        String schemaJson = """
{
    "bsonType" : "object",
    "encryptMetadata" : {
        "keyId" : [
        UUID("%s") 
        ],
        "algorithm" : "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
    },
    "properties" : {
        "name" : {
    "bsonType": "object",
        "properties" : {
        "first_name" : {
            "encrypt" : {
            "bsonType" : "string",
            "algorithm" : "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
        }
        },
        "last_name" : {
            "encrypt" : {
            "bsonType" : "string",
            "algorithm" : "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
        }
        },
        "othernames" : {
            "encrypt" : {
            "bsonType" : "string",
        }
        }
        }
    },
        "address" : {
        "bsonType" : "object",
        "properties" : {
            "streetAddress" : {
            "encrypt" : {
                "bsonType" : "string"
            }
            },
            "suburbCounty" : {
            "encrypt" : {
                "bsonType" : "string"
            }
            }
        }
        },
        "phoneNumber" : {
        "encrypt" : {
            "bsonType" : "string"
        }
        },
        "salary" : {
        "encrypt" : {
            "bsonType" : "object"
        }
        },
        "taxIdentifier" : {
        "encrypt" : {
            "bsonType" : "string"
        }
        }
    }
}
        """.formatted(dekUuid);
        BsonDocument schemaBsonDoc = BsonDocument.parse(schemaJson);
        return schemaBsonDoc;
    }

    public static void main( String[] args )
    {
        App app = new App();

        String connectionString = "mongodb+srv://mongoCryptoClient:<PASSWORD>@<CLUSTER_NAME>.bildu.mongodb.net";
        MongoNamespace keyvaultNamespace = new MongoNamespace("__encryption.__keyVault");
        String provider = "aws";

        Credentials credentials = null;
        try {
            credentials = app.getAWSToken();
        } catch (Exception e) {
            logger.error("Error getting AWS credentials.", e);
            System.exit(1);
        }

        System.out.println(credentials);
        Map<String, Map<String, Object>> kmsProvider = new HashMap<String, Map<String, Object>>();
        Map<String, Object> awsProviderInstance = new HashMap<String, Object>();
        awsProviderInstance.put("accessKeyId", credentials.accessKeyId());
        awsProviderInstance.put("secretAccessKey", credentials.secretAccessKey());
        awsProviderInstance.put("sessionToken", credentials.sessionToken());
        kmsProvider.put(provider, awsProviderInstance);

        String encryptedDbName = "companyData";
        String encryptedCollName = "employee";

        UUID  dataKey1;
        try (
            MongoClient client = app.getMdbClient(connectionString, 5000, false);
        ) {
            dataKey1 = app.getDekUUID(client, keyvaultNamespace);
        }

        BsonDocument schema = app.getSchemaDocument(dataKey1);
        Map<String, BsonDocument> schemaMap = new HashMap<String, BsonDocument>();
        schemaMap.put(encryptedDbName + "." + encryptedCollName, schema);

        Map<String, Object> extraOptions = new HashMap<String, Object>();
        //extraOptions.put("mongocryptdSpawnPath", "/Applications/mongocyptd");
        extraOptions.put("mongocryptdBypassSpawn", true);

        AutoEncryptionSettings autoEncryptionSettings = AutoEncryptionSettings.builder()
            .keyVaultNamespace(keyvaultNamespace.getFullName())
            .kmsProviders(kmsProvider)
            .extraOptions(extraOptions)
            .schemaMap(schemaMap)
            .build();

        Document payload = app.getPayload();
        if (payload.get("name", Document.class).get("othernames") == null) {
            payload.get("name", Document.class).remove("othernames");
        }

        try (MongoClient secureClient = app.getMdbClient(connectionString, 5000, false, autoEncryptionSettings)) {
            //Document encryptedPayload = app.encryptPayload(clientEncryption, schemaMap, payload, dataKey1);
            
            MongoDatabase encryptedDb = secureClient.getDatabase(encryptedDbName);
            MongoCollection<Document> encryptedColl = encryptedDb.getCollection(encryptedCollName);
            int insertedId = 0;
            try {
                ObservableSubscriber<InsertOneResult> insertSubscriber = new OperationSubscriber<InsertOneResult>();
                encryptedColl.insertOne(payload).subscribe(insertSubscriber);
                InsertOneResult inserted = insertSubscriber.first();
                insertedId = inserted.getInsertedId().asInt32().intValue();
                System.out.println(insertedId);
            } catch (MongoWriteException mwe) {
                WriteError we = mwe.getError();
                if (we.getCode() == 11000) {
                    System.err.println("Duplicate");
                    insertedId = payload.getInteger("_id");
                } else {
                    System.err.println("Error on write!");
                    mwe.printStackTrace();
                    System.exit(1);
                }
            } catch (Throwable t) {
                System.err.println("Error on write!");
                t.printStackTrace();
                System.exit(1);
            }

            ObservableSubscriber<Document> docSubscriber = new OperationSubscriber<Document>();
            encryptedColl.find(eq("_id", insertedId))
                .subscribe(docSubscriber);
            Document encryptedResult = docSubscriber.first();
            if (encryptedResult != null) {
                System.out.println(encryptedResult.toJson());
            }
        }
    }
 
}

// *** Subscribers *** //
/**
 * A Subscriber that stores the publishers results and provides a latch so can block on completion.
 *
 * @param <T> The publishers result type
 */
abstract class ObservableSubscriber<T> implements Subscriber<T> {
    private final List<T> received;
    private final List<RuntimeException> errors;
    private final CountDownLatch latch;
    private volatile Subscription subscription;

    /**
     * Construct an instance
     */
    public ObservableSubscriber() {
        this.received = new ArrayList<>();
        this.errors = new ArrayList<>();
        this.latch = new CountDownLatch(1);
    }

    @Override
    public void onSubscribe(final Subscription s) {
        subscription = s;
    }

    @Override
    public void onNext(final T t) {
        received.add(t);
    }

    @Override
    public void onError(final Throwable t) {
        if (t instanceof RuntimeException) {
            errors.add((RuntimeException) t);
        } else {
            errors.add(new RuntimeException("Unexpected exception", t));
        }
        onComplete();
    }

    @Override
    public void onComplete() {
        latch.countDown();
    }

    /**
     * Gets the subscription
     *
     * @return the subscription
     */
    public Subscription getSubscription() {
        return subscription;
    }

    /**
     * Get received elements
     *
     * @return the list of received elements
     */
    public List<T> getReceived() {
        return received;
    }

    /**
     * Get error from subscription
     *
     * @return the error, which may be null
     */
    public RuntimeException getError() {
        if (errors.size() > 0) {
            return errors.get(0);
        }
        return null;
    }

    /**
     * Get received elements.
     *
     * @return the list of receive elements
     */
    public List<T> get() {
        return await().getReceived();
    }

    /**
     * Get received elements.
     *
     * @param timeout how long to wait
     * @param unit the time unit
     * @return the list of receive elements
     */
    public List<T> get(final long timeout, final TimeUnit unit) {
        return await(timeout, unit).getReceived();
    }


    /**
     * Get the first received element.
     *
     * @return the first received element
     */
    public T first() {
        List<T> received = await().getReceived();
        return received.size() > 0 ? received.get(0) : null;
    }

    /**
     * Await completion or error
     *
     * @return this
     */
    public ObservableSubscriber<T> await() {
        return await(60, TimeUnit.SECONDS);
    }

    /**
     * Await completion or error
     *
     * @param timeout how long to wait
     * @param unit the time unit
     * @return this
     */
    public ObservableSubscriber<T> await(final long timeout, final TimeUnit unit) {
        subscription.request(Integer.MAX_VALUE);
        try {
            if (!latch.await(timeout, unit)) {
                throw new MongoTimeoutException("Publisher onComplete timed out");
            }
        } catch (InterruptedException e) {
            throw new MongoInterruptedException("Interrupted waiting for observeration", e);
        }
        if (!errors.isEmpty()) {
            throw errors.get(0);
        }
        return this;
    }
}

/**
 * A Subscriber that immediately requests Integer.MAX_VALUE onSubscribe
 *
 * @param <T> The publishers result type
 */
class OperationSubscriber<T> extends ObservableSubscriber<T> {

    @Override
    public void onSubscribe(final Subscription s) {
        super.onSubscribe(s);
        s.request(Integer.MAX_VALUE);
    }
}