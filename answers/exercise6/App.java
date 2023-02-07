package exercise6;

import static com.mongodb.client.model.Filters.eq;

import com.github.javafaker.Address;
import com.github.javafaker.Faker;
import com.mongodb.AutoEncryptionSettings;
import com.mongodb.ClientEncryptionSettings;
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
import com.mongodb.reactivestreams.client.vault.ClientEncryption;
import com.mongodb.reactivestreams.client.vault.ClientEncryptions;
import com.mongodb.client.model.Projections;
import com.mongodb.client.model.vault.DataKeyOptions;
import com.mongodb.client.result.InsertOneResult;

import org.bson.BsonBinary;
import org.bson.BsonDocument;
import org.bson.BsonDocumentReader;
import org.bson.BsonString;
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
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
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

    public UUID getEmployeeDekUUID(MongoClient client,
            String connectionString,
            Map<String, Map<String, Object>> kmsProvider, 
            String provider, 
            MongoNamespace keyvaultNamespace, 
            String id) {

        MongoDatabase keyvaultDatabase = client.getDatabase(keyvaultNamespace.getDatabaseName());
        MongoCollection<Document> keyvaultCollection = keyvaultDatabase.getCollection(keyvaultNamespace.getCollectionName());
        ObservableSubscriber<Document> docSubscriber = new OperationSubscriber<Document>();
        keyvaultCollection
            .find(eq("keyAltNames", id))
            .projection(Projections.fields(Projections.include("_id")))
            .subscribe(docSubscriber);
                
        Document employeeKeyDoc = docSubscriber.first();
        if (employeeKeyDoc == null) {
            try (ClientEncryption clientEncryption = this.getClientEncryption(connectionString, keyvaultNamespace, kmsProvider)) {
                ObservableSubscriber<BsonBinary> keySubscriber = new OperationSubscriber<BsonBinary>();
                BsonDocument masterKey = new BsonDocument();
                masterKey.append("region", new BsonString("ap-southeast-2"))
                    .append("key", new BsonString("5cb4ae1c-eee2-4359-a3c2-576f3de8f974"));
                DataKeyOptions dataKeyOptions = new DataKeyOptions()
                    .masterKey(masterKey)
                    .keyAltNames(Arrays.asList(id));
                clientEncryption.createDataKey(provider, dataKeyOptions).subscribe(keySubscriber);
                BsonBinary bsonKey = keySubscriber.first();
                return  bsonKey.asUuid();
            } 
        } else {
            UUID employeeKey = employeeKeyDoc.get("_id", UUID.class);
            return employeeKey;
        }
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
        "keyId" : "/dekAltName",
        "algorithm" : "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
    },
    "properties" : {
        "name" : {
    "bsonType": "object",
        "properties" : {
        "first_name" : {
            "encrypt" : {
            "bsonType" : "string",
            "keyId" : [ UUID("%1$s") ],
            "algorithm" : "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
        }
        },
        "last_name" : {
            "encrypt" : {
            "bsonType" : "string",
            "keyId" : [ UUID("%1$s") ],
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

    public static void main( String[] args ) {
        App app = new App();

        String connectionString = "mongodb+srv://mongoCryptoClient:<PASSWORD>@<CLUSTER_NAME>.bildu.mongodb.net";

        EmployeeGenerator employeeGenerator = new EmployeeGenerator();
        Document employee = employeeGenerator.genEmployee();

        MongoClient client = null;
        try {
            client = app.getMdbClient(connectionString, 5000, false);
        } catch (Exception ce) {
            logger.error("Error getting client", ce);
            System.exit(1);
        }

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

        UUID  dataKey1 = null;
        try {
            dataKey1 = app.getDekUUID(client, keyvaultNamespace);
        } catch (Exception dke) {
            logger.error("Error getting data key", dke);
            System.exit(1);
        }

        UUID employeeKeyId = null;
        try {
            employeeKeyId = app.getEmployeeDekUUID(client, connectionString, kmsProvider, provider, keyvaultNamespace, employee.getString("dekAltName"));
        } catch (Exception eke) {
            logger.error("Error getting employee key", eke);
            System.exit(1);
        }

        String encryptedDbName = "companyData";
        String encryptedCollName = "employee";

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

        try (MongoClient secureClient = app.getMdbClient(connectionString, 5000, false, autoEncryptionSettings)) {
            if (employee.get("name", Document.class).get("othernames") == null) {
                employee.get("name", Document.class).remove("othernames");
            }
            
            MongoDatabase encryptedDb = secureClient.getDatabase(encryptedDbName);
            MongoCollection<Document> encryptedColl = encryptedDb.getCollection(encryptedCollName);
            int insertedId = 0;
            try {
                ObservableSubscriber<InsertOneResult> insertSubscriber = new OperationSubscriber<InsertOneResult>();
                encryptedColl.insertOne(employee).subscribe(insertSubscriber);
                InsertOneResult inserted = insertSubscriber.first();
                insertedId = inserted.getInsertedId().asInt32().intValue();
                System.out.println(insertedId);
            } catch (MongoWriteException mwe) {
                WriteError we = mwe.getError();
                if (we.getCode() == 11000) {
                    System.err.println("Duplicate");
                    insertedId = employee.getInteger("_id");
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
        } finally {
            client.close();
        }
    }

    public static class EmployeeGenerator {
        Faker faker;
        Random random = new Random();
        List<String> roles = List.of("IC","Manager", "HR", "COO", "CEO", "CTO", "CISO");
        public final static int indentFactor = 4;
        public static final int MAX_EMPLOYMENT_HISTORY = 10;
        protected int yearsEmploymentHistory = 0;

        public EmployeeGenerator() {
            this(new Faker(new Locale("en-AU")));
        }

        public EmployeeGenerator(Faker faker) {
            this.faker = faker;
        }

        public List<String> getRoles() {
            Collections.shuffle(new ArrayList<String>(this.roles));
            int numRoles = this.random.nextInt(1, 3);
            return this.roles.subList(0, numRoles);
        }

        public List<Date> randDates(int points, int yearsEmploymentHistory) {
            List<Date> dates = new ArrayList<Date>();
            Date now = new Date();
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.YEAR, yearsEmploymentHistory * -1);
            Date start = cal.getTime();
            for (int i = 0; i < points; i++) {
                Date d = this.faker.date().between(start, now);
                dates.add(d);
            }
            Collections.sort(dates);
            Collections.reverse(dates);
            return dates;
        }

        public List<Double> randSalary(int points) {
            List<Double> salaries = new ArrayList<Double>();
            for (int i = 0; i < points; i++) {
                // from 80,000 to 300,000 to the nearest 100
                salaries.add(this.faker.number().numberBetween(800, 3000) * 100.0);
            }
            Collections.sort(salaries);
            Collections.reverse(salaries);
            return salaries;
        }

        /**
         * Get a list of documents representing salary history as [{ salary: <num>, startDate: ISODate(...)}, ...].
         * @param numPoints
         * @param yearsEmploymentHistory
         * @return
         */
        public List<Document> getHistory(int numPoints, int yearsEmploymentHistory) {
            List<Document> history = new ArrayList<Document>();

            List<Date> dates = this.randDates(numPoints, yearsEmploymentHistory);
            List<Double> salaries = this.randSalary(numPoints);
            for (int i = 0; i < numPoints; i++) {
                Document salaryPoint = new Document();
                Double salary = salaries.get(i);
                salaryPoint.append("salary", salary);
                Date date = dates.get(i);
                salaryPoint.append("startDate", date);
                history.add(salaryPoint);
            }
            return history;
        }

        public Document realRandomAddress() {
            Address address = this.faker.address();
            Document docAddress = new Document();
            docAddress.put("streetAddress", address.streetAddress());
            docAddress.put("suburbCounty", address.city());
            docAddress.put("stateProvince", address.state());
            docAddress.put("zipPostcode", address.zipCode());
            docAddress.put("country", address.country());
            //return docAddress.toString(indentFactor);
            return docAddress;
        }

        public int getId() {
            //return String.format("%s", (10000 + this.random.nextInt(90000)));
            return 10000 + this.random.nextInt(90000);
        }

        public String getFirstName() {
            return this.faker.name().firstName();
        }

        public String getLastName() {
            return this.faker.name().lastName(); 
        }

        public String getOtherName() {
            return (this.random.nextBoolean()) ? this.faker.name().firstName() : null ;
        }

        public Date getDoB(int years) {
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.YEAR, -100);
            Date start = cal.getTime();
            cal = Calendar.getInstance();
            cal.add(Calendar.YEAR, yearsEmploymentHistory * -1 - 18);
            Date end = cal.getTime();
            return this.faker.date().between(start, end);
        }

        public String genPhone() {
            return this.faker.phoneNumber().toString();
        }

        public Document genEmployee() {

            int yearsEmploymentHistory = this.random.nextInt(2, MAX_EMPLOYMENT_HISTORY);
            int salaryPoints = this.random.nextInt(1, yearsEmploymentHistory);
            List<Document> salaryHistory = this.getHistory(salaryPoints, yearsEmploymentHistory);
            Document currSalary = salaryHistory.get(0);
            double salaryCurrent = currSalary.getDouble("salary");
            Date salaryStartDate = currSalary.getDate("startDate");
            Document salary = new Document();
            salary.append("current", salaryCurrent)
                .append("startDate", salaryStartDate)
                .append("history", salaryHistory);

            Document name = new Document();
            name.append("first_name", this.getFirstName());
            name.append("last_name", this.getLastName());
            name.append("othernames", this.getOtherName());
            Document doc = new Document();
            int id = this.getId();
            doc.append("_id", id)
                .append("name", name)
                .append("address", this.realRandomAddress())
                .append("dob", this.getDoB(yearsEmploymentHistory))
                .append("phoneNumber", this.genPhone())
                .append("salary", salary)
                .append("taxIdentifier", Integer.toString(this.faker.number().numberBetween(100000000, 1000000000 - 1)))
                .append("role", this.getRoles())
                .append("dekAltName", Integer.toString(id));
            return doc;
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