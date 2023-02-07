package exercise2;

import static com.mongodb.client.model.Filters.eq;

import com.mongodb.AutoEncryptionSettings;
import com.mongodb.ClientEncryptionSettings;
import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoNamespace;
import com.mongodb.ServerApi;
import com.mongodb.ServerApiVersion;
import com.mongodb.reactivestreams.client.MongoClient;
import com.mongodb.reactivestreams.client.MongoClients;
import com.mongodb.reactivestreams.client.MongoCollection;
import com.mongodb.reactivestreams.client.MongoDatabase;
import com.mongodb.client.model.Projections;
import com.mongodb.client.model.vault.EncryptOptions;
import com.mongodb.client.result.InsertOneResult;
import com.mongodb.reactivestreams.client.vault.ClientEncryption;
import com.mongodb.reactivestreams.client.vault.ClientEncryptions;

import org.bson.BsonBinary;
import org.bson.BsonDocument;
import org.bson.BsonDocumentReader;
import org.bson.BsonValue;
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

import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

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

    public ClientEncryption getClientEncryption(String connectionString, MongoNamespace keyvaultNamespace, Map<String, Map<String, Object>> kmsProviders) {
        ClientEncryptionSettings encryptionSettings = ClientEncryptionSettings.builder()
            .keyVaultMongoClientSettings(MongoClientSettings.builder()
                .applyConnectionString(new ConnectionString(connectionString))
                .uuidRepresentation(UuidRepresentation.STANDARD)
                .build())
            .keyVaultNamespace(keyvaultNamespace.getFullName())
            .kmsProviders(kmsProviders)    
            .build();
        
        ClientEncryption clientEncryption = ClientEncryptions.create(encryptionSettings);
        return clientEncryption;
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
  "_id": 2316,
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
  
    /**
     * Count the number of fields in the schemaMap.
     * 
     * @param schemaMap
     * @return
     */
    public static int countFields(Map<String, String[][]> schemaMap) {
        // Calculate the number of fields to decrypt
        int numEncryptedFields = 0;
        for (String algorithm : schemaMap.keySet()) {
            String[][] deepKeyArray = schemaMap.get(algorithm);
            numEncryptedFields += deepKeyArray.length;
        }

        return numEncryptedFields;
    }

    public Document encryptPayload(ClientEncryption clientEncryption, Map<String, String[][]> schemaMap, Document payload, UUID dataKey1) 
            throws InterruptedException {
        BsonDocument encryptedPayload = payload.toBsonDocument();
        // latch to wait for all fields to by en/decrypted
        CountDownLatch allFieldsLatch = new CountDownLatch(countFields(schemaMap));

        for (String algorithm : schemaMap.keySet()) {
            EncryptOptions options = new EncryptOptions(algorithm).keyId(new BsonBinary(dataKey1));
            String[][] deepKeyArray = schemaMap.get(algorithm);
            for (String[] deepKeys : deepKeyArray) {
                try {
                    BsonValue val = nestedGet(encryptedPayload, deepKeys);
                    if (val != null) {
                        ObservableSubscriber<BsonValue> valueSetter = new ConsumerSubscriber<BsonValue>(
                            encVal -> nestedSet(encryptedPayload, deepKeys, encVal),
                            allFieldsLatch
                        );
                        encryptData(val, clientEncryption, options).subscribe(valueSetter);
                        
                    } else {
                        allFieldsLatch.countDown();
                        nestedRemove(encryptedPayload, deepKeys);
                    }
                } catch (Exception bve) {
                    System.err.println("Error in encryptPayload on [" + String.join(", ", deepKeys) + "]");
                    bve.printStackTrace();
                }
            }
        }
        // Make sure all encryptions have completed before returning the doc
        allFieldsLatch.await(60, TimeUnit.SECONDS);
        return toDoc(encryptedPayload);
    }

    public BsonValue nestedGet(BsonDocument doc, String[] deepKeys) {
        int idx;
        for (idx=0; idx < deepKeys.length - 1; idx++) {
            doc = (BsonDocument) doc.get(deepKeys[idx]);
        }
        return doc.get(deepKeys[idx]);
    }

    public void nestedSet(BsonDocument doc, String[] deepKeys, BsonValue val) {
        int idx;
        for (idx=0; idx < deepKeys.length - 1; idx++) {
            doc = (BsonDocument) doc.get(deepKeys[idx]);
        }
        doc.put(deepKeys[idx], val);
    }

    public void nestedRemove(BsonDocument doc, String[] deepKeys) {
        int idx;
        for (idx=0; idx < deepKeys.length - 1; idx++) {
            doc = (BsonDocument) doc.get(deepKeys[idx]);
        }
        doc.remove(deepKeys[idx]);
    }

    public Publisher<BsonBinary> encryptData(BsonValue data,  ClientEncryption clientEncryption, EncryptOptions options) {
        return clientEncryption.encrypt(data, options);
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

        try (
            MongoClient client = app.getMdbClient(connectionString, 5000, false);
            ClientEncryption clientEncryption = app.getClientEncryption(connectionString, keyvaultNamespace, kmsProvider);
        ) {

            UUID dataKey1 = app.getDekUUID(client, keyvaultNamespace);

            Document payload = app.getPayload();
            if (payload.get("name", Document.class).get("othernames") == null) {
                payload.get("name", Document.class).remove("othernames");
            }

            Map<String, String[][]> schemaMap = new HashMap<String, String[][]>();
            schemaMap.put("AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", new String[][] {
                new String[]{"name", "first_name"},
                new String[]{"name", "last_name"},
            });
            schemaMap.put("AEAD_AES_256_CBC_HMAC_SHA_512-Random", new String[][] {
                new String[]{"name", "othernames"},
                new String[]{"address", "streetAddress"},
                new String[]{"address", "suburbCounty"},
                new String[]{"dob"},
                new String[]{"phoneNumber"},
                new String[]{"salary"},
                new String[]{"taxIdentifier"},
            });

            Document encryptedPayload = null;
            try {
                encryptedPayload = app.encryptPayload(clientEncryption, schemaMap, payload, dataKey1);
            } catch (Exception pe) {
                System.err.println("Error on payload encryption!");
                pe.printStackTrace();
                System.exit(1);
            }    
            
            MongoDatabase encryptedDb = client.getDatabase(encryptedDbName);
            MongoCollection<Document> encryptedColl = encryptedDb.getCollection(encryptedCollName);
            ObservableSubscriber<InsertOneResult> insertSubscriber = new OperationSubscriber<InsertOneResult>();
            InsertOneResult inserted = null;
            encryptedColl.insertOne(encryptedPayload).subscribe(insertSubscriber);
            try {
                inserted = insertSubscriber.first();
            } catch (Throwable t) {
                System.err.println("Error on write!");
                t.printStackTrace();
                System.exit(1);
            }
            int insertedId = inserted.getInsertedId().asInt32().intValue();
            System.out.println(insertedId);
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
        this(new CountDownLatch(1));
    }

    public ObservableSubscriber(CountDownLatch latch) {
        this.received = new ArrayList<>();
        this.errors = new ArrayList<>();
        this.latch = latch;
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
        // System.out.println("Latch count: " + latch.getCount());
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

    public OperationSubscriber() {
        super();
    }

    public OperationSubscriber(CountDownLatch latch) {
        super(latch);
    }

    @Override
    public void onSubscribe(final Subscription s) {
        super.onSubscribe(s);
        s.request(Integer.MAX_VALUE);
    }
}

/**
 * A Subscriber that processes a consumer for each element
 * @param <T> the type of the element
 */
class ConsumerSubscriber<T> extends OperationSubscriber<T> {
    private final Consumer<T> consumer;

    /**
     * Construct a new instance
     * @param consumer the consumer
     */
    public ConsumerSubscriber(final Consumer<T> consumer) {
        this.consumer = consumer;
    }

    public ConsumerSubscriber(final Consumer<T> consumer, CountDownLatch latch) {
        super(latch);
        this.consumer = consumer;
    }

    @Override
    public void onNext(final T document) {
        super.onNext(document);
        consumer.accept(document);
    }
}