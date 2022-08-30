db.getSiblingDB("companyData").createCollection("employee",
 {
   "validator": {
     "$jsonSchema": {
       "bsonType" : "object",
       "encryptMetadata" : {
         "keyId" : [
           UUID("d7e6d56f-7f03-4d3f-9de7-73e12ebcf3ec")
         ],
         "algorithm" : "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
       },
       "properties" : {
         "name" : {
		"bsonType": "object",
		  "properties" : {
		    "firstname" : {
		      "encrypt" : {
			  "bsonType" : "string",
			  "algorithm" : "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
			}
		    },
		    "lastname" : {
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
   }
 }
)
