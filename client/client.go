package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string
	Password string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// HELPER FUNCTIONS //

func SymmetricKeyGenFromSourceKey(sourceKey []byte, purpose string) (derivedEncKey []byte, derivedMacKey []byte, err error) {

	derivedEncKey, err = userlib.HashKDF(sourceKey, []byte("symmetric ENC key for"+purpose))
	if err != nil {
		return nil, nil, errors.New("symmetric ENC key generation failed")
	}

	derivedMacKey, err = userlib.HashKDF(sourceKey, []byte("symetric MAC key for"+purpose))
	if err != nil {
		return nil, nil, errors.New("symmetric MAC key generation failed")
	}

	//userlib.DebugMsg("Keys are", derivedEncKey, derivedMacKey)
	return derivedEncKey, derivedMacKey, nil
}

func SymmetricEncryptAndTag(sourceKey []byte, purpose string, contentBytes []byte) (ciphertext []byte, tag []byte, err error) {

	// FOR DEBUGGING - ensure that inputs are the same for determinism
	// userlib.DebugMsg("Dec key is; %v", decKeyUnsliced[:16])
	// userlib.DebugMsg("Mac key is: %v", macKeyUnsliced[:16])
	// userlib.DebugMsg("Ciphertext is: %v", ciphertext)
	// userlib.DebugMsg("Tag is: %v", tag)
	// userlib.DebugMsg("Beginning encryption and tagging!")

	encKeyUnsliced, macKeyUnsliced, err := SymmetricKeyGenFromSourceKey(sourceKey, purpose)
	if err != nil {
		return nil, nil, errors.New("symmetric key generation failed")
	}

	ciphertext = userlib.SymEnc(encKeyUnsliced[:16], userlib.RandomBytes(16), contentBytes)

	tag, err = userlib.HMACEval(macKeyUnsliced[:16], ciphertext)
	if err != nil {
		return nil, nil, errors.New("MAC tag generation failed")
	}

	return ciphertext, tag, nil
}

func SymmetricTagAndDecrypt(sourceKey []byte, purpose string, ciphertext []byte, tag []byte) (contentBytes []byte, err error) {

	// FOR DEBUGGING - ensure that inputs are the same for determinism
	// userlib.DebugMsg("Dec key is; %v", decKeyUnsliced[:16])
	// userlib.DebugMsg("Mac key is: %v", macKeyUnsliced[:16])
	// userlib.DebugMsg("Ciphertext is: %v", ciphertext)
	// userlib.DebugMsg("Tag is: %v", tag)
	// userlib.DebugMsg("Beginning tag check and decryption!")

	decKeyUnsliced, macKeyUnsliced, err := SymmetricKeyGenFromSourceKey(sourceKey, purpose)
	if err != nil {
		userlib.DebugMsg("Key gen failed")
		return nil, err
	}

	confirmationTag, err := userlib.HMACEval(macKeyUnsliced[:16], ciphertext)
	if err != nil {
		userlib.DebugMsg("MAC confirmation tag generation failed")
		return nil, errors.New("MAC confirmation tag generation failed")
	}

	if !userlib.HMACEqual(confirmationTag, tag) {
		userlib.DebugMsg("not matching")
		return nil, errors.New("MACs do not match - tampering detected")
	}

	contentBytes = userlib.SymDec(decKeyUnsliced[:16], ciphertext)

	return contentBytes, nil
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	var userSourceKey []byte
	var userUUID uuid.UUID
	var datastoreContent []byte
	userdata.Username = username

	// check if username is empty string
	if username == "" {
		return &userdata, err
	}

	// hash username and convert to UUID
	userUUID, err = uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return &userdata, err
	}

	// check if UUID already exists in datastore
	if _, ok := userlib.DatastoreGet(userUUID); ok {
		return &userdata, err
	}

	// prepare source key and datastore content for encryption
	userSourceKey = userlib.Argon2Key([]byte(password), []byte(username), 16)
	datastoreContent, err = json.Marshal(userdata)
	if err != nil {
		return &userdata, err
	}

	// datastore content is encrypted
	ciphertext, ciphertextMAC, err := SymmetricEncryptAndTag(userSourceKey, "storing user structs", datastoreContent)
	if err != nil {
		return &userdata, err
	}

	userlib.DatastoreSet(userUUID, append(ciphertext, ciphertextMAC...))

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	var userSourceKey []byte
	var userUUID uuid.UUID
	var ciphertextPlusMac []byte
	userdataptr = &userdata

	// check if username is empty string
	if username == "" {
		return &userdata, errors.New("username is empty string")
	}

	// hash username and convert to UUID
	userUUID, err = uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return &userdata, err
	}

	// fetch user struct from datastore and parse it
	ciphertextPlusMac, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return &userdata, err
	}
	ciphertext := ciphertextPlusMac[0 : len(ciphertextPlusMac)-64]
	ciphertextMac := ciphertextPlusMac[len(ciphertextPlusMac)-64:]

	// generate decryption keys on the fly
	userSourceKey = userlib.Argon2Key([]byte(password), []byte(username), 16)

	// check tag and decrypt fetched user struct from datastore
	contentBytes, err := SymmetricTagAndDecrypt(userSourceKey, "storing user structs", ciphertext, ciphertextMac)
	if err != nil {
		userlib.DebugMsg("Symmetric decryption failed.")
		return &userdata, err
	}

	// unmarshal decrypted bytes
	json.Unmarshal(contentBytes, userdataptr)

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// storageUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	// // storageKey is not a key! key as in UUID for the datastore
	// if err != nil {
	// 	return err
	// }
	// contentBytes, err := json.Marshal(content)
	// if err != nil {
	// 	return err
	// }

	// // generate encryption and MAC keys for file blobs
	// userSourceKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
	// userEncKeyUnsliced, err := userlib.HashKDF(userSourceKey, []byte("sym enc key for files"))
	// if err != nil {
	// 	return err
	// }
	// userMacKeyUnsliced, err := userlib.HashKDF(userSourceKey, []byte("sym mac key for user files"))
	// if err != nil {
	// 	return err
	// }

	// // generate ciphertext and tag to store at storageUUID
	// ciphertext := userlib.SymEnc(userEncKeyUnsliced[:16], userlib.RandomBytes(16), contentBytes)
	// if err != nil {
	// 	return err
	// }
	// ciphertextMAC, err := userlib.HMACEval(userMacKeyUnsliced[:16], ciphertext)
	// if err != nil {
	// 	return err
	// }

	// userlib.DatastoreSet(storageUUID, append(ciphertext, ciphertextMAC...))

	// // once file is stored, reset num appends to 0
	// // generate encryption and MAC keys for numappends
	// numAppendsUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "num appends"))[:16])
	// if err != nil {
	// 	return err
	// }

	// numAppendsEncKeyUnsliced, err := userlib.HashKDF(userSourceKey, []byte("sym enc key for num appends"))
	// if err != nil {
	// 	return err
	// }
	// numAppendsMacKeyUnsliced, err := userlib.HashKDF(userSourceKey, []byte("sym mac key for num appends"))
	// if err != nil {
	// 	return err
	// }

	// ciphertext = userlib.SymEnc(numAppendsEncKeyUnsliced[:16], userlib.RandomBytes(16), contentBytes)
	// if err != nil {
	// 	return err
	// }
	// ciphertextMAC, err = userlib.HMACEval(numAppendsMacKeyUnsliced[:16], ciphertext)
	// if err != nil {
	// 	return err
	// }

	// userlib.DatastoreSet(numAppendsUUID, append(ciphertext, ciphertextMAC...))

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}

	// // get number of file appends from numappends UUID
	// numAppendsUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "num appends"))[:16])
	// if err != nil {
	// 	return nil, err
	// }

	// numAppends, ok := userlib.DatastoreGet(numAppendsUUID)
	// if !ok {
	// 	return errors.New("no number of appends")
	// }

	// // decrypt and check NUMBER OF APPENDS struct for tampering

	// // for number of file appends
	// // 		load in file blob and append contents to dataJSON
	// for count := 0; count < numAppends; count++ {
	// 	thisFileBlob :=
	// 	dataJSON = append(dataJSON, something)
	// }

	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
