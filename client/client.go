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
	_ "strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	"strconv"
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
	//map[KeyType]ValueType
	OwnedFilesDirLoc    uuid.UUID
	ReceivedFilesDirLoc uuid.UUID
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type FileMetadata struct {
	FileLocation  userlib.UUID
	FileSourceKey []byte
	NumAppends    int
}

// HELPER FUNCTIONS //

func IntToByteArray(integer int) []byte {
	return []byte(strconv.Itoa(integer))
}

func DecryptFileDirectories(userSourceKey []byte, ownedFilesDirLoc uuid.UUID, receivedFilesDirLoc uuid.UUID) (ownedFilesDir map[string]uuid.UUID, receivedFilesDir map[string]uuid.UUID, err error) {

	// fetch received files directory from datastore
	ciphertext, ciphertextMac, err := ParseCiphertextandTagFromDatastore(receivedFilesDirLoc)
	if err != nil {
		userlib.DebugMsg("Fetching ciphertext from datastore failed.")
		return nil, nil, err
	}

	// check tag and decrypt from datastore
	contentBytes, err := SymmetricTagAndDecrypt(userSourceKey, "storing received files directory", ciphertext, ciphertextMac)
	if err != nil {
		userlib.DebugMsg("Symmetric decryption failed.")
		return nil, nil, err
	}
	json.Unmarshal(contentBytes, &receivedFilesDir)
	userlib.DebugMsg("received files directory: %v", receivedFilesDir)

	// fetch owned files directory from datastore
	ciphertext, ciphertextMac, err = ParseCiphertextandTagFromDatastore((ownedFilesDirLoc))
	if err != nil {
		userlib.DebugMsg("Fetching ciphertext from datastore failed.")
		return nil, nil, err
	}

	// check tag and decrypt from datastore
	contentBytes, err = SymmetricTagAndDecrypt(userSourceKey, "storing owned files directory", ciphertext, ciphertextMac)
	if err != nil {
		userlib.DebugMsg("Symmetric decryption failed.")
		return nil, nil, err
	}
	json.Unmarshal(contentBytes, &ownedFilesDir)
	userlib.DebugMsg("owned files directory: %v", ownedFilesDir)
	return ownedFilesDir, receivedFilesDir, nil
}

func CheckForFileInUserNamespace() {

}

func SymmetricKeyGenFromSourceKey(sourceKey []byte, purpose string) (derivedEncKey []byte, derivedMacKey []byte, err error) {

	derivedEncKey, err = userlib.HashKDF(sourceKey, []byte("symmetric ENC key for"+purpose))
	if err != nil {
		return nil, nil, errors.New("symmetric ENC key generation failed")
	}

	derivedMacKey, err = userlib.HashKDF(sourceKey, []byte("symmetric MAC key for"+purpose))
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
	//userlib.DebugMsg("keys are %v, %v", decKeyUnsliced, macKeyUnsliced)
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
		userlib.DebugMsg("MACs do not match - tampering detected.")
		return nil, errors.New("MACs do not match - tampering detected")
	}

	contentBytes = userlib.SymDec(decKeyUnsliced[:16], ciphertext)

	return contentBytes, nil
}

func ParseCiphertextandTagFromDatastore(uuid uuid.UUID) (ciphertext []byte, tag []byte, err error) {
	ciphertextPlusMac, ok := userlib.DatastoreGet(uuid)
	if !ok {
		userlib.DebugMsg("No data exists at this UUID.")
		return nil, nil, err
	}
	ciphertext = ciphertextPlusMac[0 : len(ciphertextPlusMac)-64]
	tag = ciphertextPlusMac[len(ciphertextPlusMac)-64:]
	return ciphertext, tag, nil
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	var userSourceKey []byte
	var userUUID uuid.UUID
	var datastoreContent []byte
	var ownedFilesContent []byte
	var receivedFilesContent []byte
	userdata.Username = username
	userdata.Password = password

	// check if username is empty string
	if username == "" {
		return &userdata, err
	}

	// store owned and received files directory locations in datastore and in local memory
	ownedFilesDirUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + "owned files"))[:16])
	if err != nil {
		userlib.DebugMsg("ownedFilesDirUUID generation failed.")
		return &userdata, err
	}
	receivedFilesDirUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + "received files"))[:16])
	if err != nil {
		userlib.DebugMsg("receivedFilesDirUUID generation failed.")
		return &userdata, err
	}
	userdata.OwnedFilesDirLoc = ownedFilesDirUUID
	userdata.ReceivedFilesDirLoc = receivedFilesDirUUID
	userlib.DebugMsg("received files directory is %v", userdata.ReceivedFilesDirLoc)

	// symmetrically encrypt an empty map to each directory
	userSourceKey = userlib.Argon2Key([]byte(password), []byte(username), 16)
	// userlib.DebugMsg("userSourceKey is %v", userSourceKey)
	emptyFileDir := make(map[string]uuid.UUID)
	ownedFilesContent, err = json.Marshal(emptyFileDir)
	if err != nil {
		userlib.DebugMsg("ownedFilesContent could not be marshaled.")
		return &userdata, err
	}
	receivedFilesContent, err = json.Marshal(emptyFileDir)
	if err != nil {
		userlib.DebugMsg("receivedFilesContent could not be marshaled.")
		return &userdata, err
	}

	ownedFilesDirCiphertext, ownedFilesDirCiphertextMAC, err :=
		SymmetricEncryptAndTag(userSourceKey, "storing owned files directory", ownedFilesContent)
	//userlib.DebugMsg("ciphertext, ciphertextMac are %v, %v", ownedFilesDirCiphertext, ownedFilesDirCiphertextMAC)
	if err != nil {
		userlib.DebugMsg("Symmetric encryption failed.")
		return &userdata, err
	}

	receivedFilesDirCiphertext, receivedFilesDirCiphertextMAC, err :=
		SymmetricEncryptAndTag(userSourceKey, "storing received files directory", receivedFilesContent)
	//userlib.DebugMsg("ciphertext, ciphertextMac are %v, %v", ownedFilesDirCiphertext, ownedFilesDirCiphertextMAC)
	if err != nil {
		userlib.DebugMsg("Symmetric encryption failed.")
		return &userdata, err
	}
	userlib.DatastoreSet(ownedFilesDirUUID, append(ownedFilesDirCiphertext, ownedFilesDirCiphertextMAC...))
	userlib.DatastoreSet(receivedFilesDirUUID, append(receivedFilesDirCiphertext, receivedFilesDirCiphertextMAC...))

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
	datastoreContent, err = json.Marshal(userdata)
	if err != nil {
		return &userdata, err
	}

	// datastore content is encrypted
	userStructCiphertext, userStructCiphertextMAC, err := SymmetricEncryptAndTag(userSourceKey, "storing user structs", datastoreContent)
	if err != nil {
		return &userdata, err
	}

	userlib.DatastoreSet(userUUID, append(userStructCiphertext, userStructCiphertextMAC...))

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	var userSourceKey []byte
	var userUUID uuid.UUID
	// var ciphertextPlusMac []byte
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
	ciphertext, ciphertextMac, err := ParseCiphertextandTagFromDatastore(userUUID)
	if err != nil {
		userlib.DebugMsg("Fetching ciphertext from datastore failed.")
		return &userdata, err
	}

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
	var userSourceKey []byte
	var ownedFilesDir map[string]uuid.UUID
	var receivedFilesDir map[string]uuid.UUID
	var fileMetadata FileMetadata
	var fileMetadataUUID uuid.UUID

	// PROCEED only if file is not in received files dictionary

	// if file is not in owned files dictionary (never been initialized before and therefore has no metadata)
	// -- encrypt an additional file metadata struct
	// ---- generate random symmetric keys for initialized file
	// ---- generate random UUID for file
	// ---- set numAppends count to 0
	// -- store file contents at a random UUID
	// -- add to owned files dictionary (label: filename, value: location of file MD)

	// if file IS in owned files dictionary (already been initialized and no need to encrypt metadata struct)
	// -- go to filedata struct and set numAppends count to 0
	// -- go to random UUID and set filecontents to input string
	// -- reset all appends to empty strings

	// fetch user struct from datastore and parse it
	ciphertext, ciphertextMac, err := ParseCiphertextandTagFromDatastore(userdata.ReceivedFilesDirLoc)
	//userlib.DebugMsg("received files directory is %v", userdata.ReceivedFilesDirLoc)
	//userlib.DebugMsg("ciphertext, ciphertextMac are %v, %v", ciphertext, ciphertextMac)
	if err != nil {
		userlib.DebugMsg("Fetching ciphertext from datastore failed.")
		return err
	}
	//userlib.DebugMsg("username: %v, password: %v", userdata.Username, userdata.Password)
	userSourceKey = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
	//userlib.DebugMsg("userSourceKey is: %v", userSourceKey)

	// check tag and decrypt fetched user struct from datastore
	contentBytes, err := SymmetricTagAndDecrypt(userSourceKey, "storing received files directory", ciphertext, ciphertextMac)
	if err != nil {
		userlib.DebugMsg("Symmetric decryption failed.")
		return err
	}
	json.Unmarshal(contentBytes, &receivedFilesDir)

	// check if file is already in received files directory
	_, ok := receivedFilesDir[filename]
	if ok {
		userlib.DebugMsg("File already in received files directory.")
		return errors.New("file already in received files directory")
	}

	// fetch owned files directory from datastore
	ciphertext, ciphertextMac, err = ParseCiphertextandTagFromDatastore((userdata.OwnedFilesDirLoc))
	if err != nil {
		userlib.DebugMsg("Fetching ciphertext from datastore failed.")
		return err
	}
	contentBytes, err = SymmetricTagAndDecrypt(userSourceKey, "storing owned files directory", ciphertext, ciphertextMac)
	if err != nil {
		userlib.DebugMsg("Symmetric decryption failed.")
		return err
	}
	json.Unmarshal(contentBytes, &ownedFilesDir)

	// check if file is already in owned files directory
	fileMetadataUUID, ok = ownedFilesDir[filename]

	// if doesn't exist in owned files, then create file metadata struct and store in owned files directory
	if !ok {
		fileMetadataUUID = uuid.New()
		fileLocation := uuid.New()
		fileSourceKey := userlib.RandomBytes(16)
		fileNumAppends := 0

		fileMetadata = FileMetadata{fileLocation, fileSourceKey, fileNumAppends}

		ownedFilesDir[filename] = fileMetadataUUID
		ownedFilesContent, err := json.Marshal(ownedFilesDir)
		if err != nil {
			userlib.DebugMsg("ownedFilesContent could not be marshaled.")
			return err
		}

		ownedFilesDirCiphertext, ownedFilesDirCiphertextMAC, err :=
			SymmetricEncryptAndTag(userSourceKey, "storing owned files directory", ownedFilesContent)
		if err != nil {
			userlib.DebugMsg("Symmetric encryption failed.")
			return err
		}

		userlib.DatastoreSet(userdata.OwnedFilesDirLoc, append(ownedFilesDirCiphertext, ownedFilesDirCiphertextMAC...))
	} else {
		// if file IS in owned files dictionary (already been initialized and no need to create metadata struct)
		// -- go to filemetadata struct and set numAppends count to 0
		// -- go to random UUID and set filecontents to input string
		// -- reset all appends to empty strings
		ciphertext, ciphertextMac, err = ParseCiphertextandTagFromDatastore(userdata.OwnedFilesDirLoc)
		if err != nil {
			userlib.DebugMsg("Fetching ciphertext from datastore failed.")
			return err
		}
		contentBytes, err = SymmetricTagAndDecrypt(userSourceKey, "storing owned files directory", ciphertext, ciphertextMac)
		if err != nil {
			userlib.DebugMsg("Symmetric decryption failed.")
			return err
		}
		json.Unmarshal(contentBytes, &fileMetadata)

		// fileMetadata = FileMetadata{fileLocation, fileSourceKey, fileNumAppends}
	}
	// reset number of appends for file
	fileMetadata.NumAppends = 0

	// re-encrypt file metadata struct
	fileMDContent, err := json.Marshal(fileMetadata)
	if err != nil {
		userlib.DebugMsg("fileMetadataContent could not be marshaled.")
		return err
	}

	fileMDCiphertext, fileMDCiphertextMAC, err :=
		SymmetricEncryptAndTag(userSourceKey, "storing file metadata", fileMDContent)
	if err != nil {
		userlib.DebugMsg("Symmetric encryption failed.")
		return err
	}

	userlib.DatastoreSet(fileMetadataUUID, append(fileMDCiphertext, fileMDCiphertextMAC...))

	// store contents in file
	fileUUID := fileMetadata.FileLocation
	fileSourceKey := fileMetadata.FileSourceKey
	// fileNumAppends := fileMetadata.NumAppends
	fileContent, err := json.Marshal(content)
	if err != nil {
		userlib.DebugMsg("fileContent could not be marshaled.")
		return err
	}

	fileContentCiphertext, fileContentCiphertextMac, err :=
		SymmetricEncryptAndTag(fileSourceKey, "storing file contents", fileContent)
	if err != nil {
		userlib.DebugMsg("Symmetric encryption failed.")
		return err
	}

	userlib.DatastoreSet(fileUUID, append(fileContentCiphertext, fileContentCiphertextMac...))

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var userSourceKey []byte
	var ownedFilesDir map[string]uuid.UUID
	var receivedFilesDir map[string]uuid.UUID
	var fileMetadataUUID uuid.UUID
	var fileMetadata FileMetadata

	userSourceKey = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
	// fetch received files directory from datastore
	ciphertext, ciphertextMac, err := ParseCiphertextandTagFromDatastore(userdata.ReceivedFilesDirLoc)
	if err != nil {
		userlib.DebugMsg("Fetching ciphertext from datastore failed.")
		return err
	}

	// check tag and decrypt from datastore
	contentBytes, err := SymmetricTagAndDecrypt(userSourceKey, "storing received files directory", ciphertext, ciphertextMac)
	if err != nil {
		userlib.DebugMsg("Symmetric decryption failed.")
		return err
	}
	json.Unmarshal(contentBytes, &receivedFilesDir)

	// fetch owned files directory from datastore
	ciphertext, ciphertextMac, err = ParseCiphertextandTagFromDatastore((userdata.OwnedFilesDirLoc))
	if err != nil {
		userlib.DebugMsg("Fetching ciphertext from datastore failed.")
		return err
	}

	// check tag and decrypt from datastore
	contentBytes, err = SymmetricTagAndDecrypt(userSourceKey, "storing owned files directory", ciphertext, ciphertextMac)
	if err != nil {
		userlib.DebugMsg("Symmetric decryption failed.")
		return err
	}
	json.Unmarshal(contentBytes, &ownedFilesDir)

	// check if filename is in namespace
	_, inReceivedFilesDir := receivedFilesDir[filename]
	_, inOwnedFilesDir := ownedFilesDir[filename]
	if !inReceivedFilesDir && !inOwnedFilesDir {
		userlib.DebugMsg("Filename not in namespace.")
		return err
	} else if inReceivedFilesDir {
		fileMetadataUUID = receivedFilesDir[filename]
	} else if inOwnedFilesDir {
		fileMetadataUUID = ownedFilesDir[filename]
	}

	// access file metadata and increment number of appends
	ciphertext, ciphertextMac, err = ParseCiphertextandTagFromDatastore(fileMetadataUUID)
	if err != nil {
		userlib.DebugMsg("Fetching ciphertext from datastore failed.")
		return err
	}
	contentBytes, err = SymmetricTagAndDecrypt(userSourceKey, "storing file metadata", ciphertext, ciphertextMac)
	if err != nil {
		userlib.DebugMsg("Symmetric decryption failed.")
		return err
	}
	json.Unmarshal(contentBytes, &fileMetadata)

	fileMetadata.NumAppends += 1

	// re-encrypt file metadata
	fileMDContent, err := json.Marshal(fileMetadata)
	if err != nil {
		userlib.DebugMsg("fileMetadataContent could not be marshaled.")
		return err
	}

	fileMDCiphertext, fileMDCiphertextMAC, err :=
		SymmetricEncryptAndTag(userSourceKey, "storing file metadata", fileMDContent)
	if err != nil {
		userlib.DebugMsg("Symmetric encryption failed.")
		return err
	}

	userlib.DatastoreSet(fileMetadataUUID, append(fileMDCiphertext, fileMDCiphertextMAC...))

	// hash fileUUID with number of appends to get unique UUID
	fileLocation := fileMetadata.FileLocation
	numAppends := IntToByteArray(fileMetadata.NumAppends)
	fileAppendUUID, err := uuid.FromBytes(userlib.Hash(append(fileLocation[:], numAppends...))[:16])
	if err != nil {
		userlib.DebugMsg("fileUUID generation failed.")
		return err
	}

	// store content at fileUUID using fileSourceKey
	fileSourceKey := fileMetadata.FileSourceKey
	fileAppendContent, err := json.Marshal(content)
	if err != nil {
		userlib.DebugMsg("fileContent could not be marshaled.")
		return err
	}

	fileAppendCiphertext, fileAppendCiphertextMac, err :=
		SymmetricEncryptAndTag(fileSourceKey, "storing file contents", fileAppendContent)
	if err != nil {
		userlib.DebugMsg("Symmetric encryption failed.")
		return err
	}

	userlib.DatastoreSet(fileAppendUUID, append(fileAppendCiphertext, fileAppendCiphertextMac...))

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var userSourceKey []byte
	var ownedFilesDir map[string]uuid.UUID
	var receivedFilesDir map[string]uuid.UUID
	var fileMetadataUUID uuid.UUID
	var fileMetadata FileMetadata
	var thisContent []byte

	// storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	// if err != nil {
	// 	return nil, err
	// }
	// dataJSON, ok := userlib.DatastoreGet(storageKey)
	// if !ok {
	// 	return nil, errors.New(strings.ToTitle("file not found"))
	// }

	userSourceKey = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
	// fetch received files directory from datastore
	// ciphertext, ciphertextMac, err := ParseCiphertextandTagFromDatastore(userdata.ReceivedFilesDirLoc)
	// if err != nil {
	// 	userlib.DebugMsg("Fetching ciphertext from datastore failed.")
	// 	return nil, err
	// }

	// // check tag and decrypt from datastore
	// contentBytes, err := SymmetricTagAndDecrypt(userSourceKey, "storing received files directory", ciphertext, ciphertextMac)
	// if err != nil {
	// 	userlib.DebugMsg("Symmetric decryption failed.")
	// 	return nil, err
	// }
	// json.Unmarshal(contentBytes, &receivedFilesDir)

	// userlib.DebugMsg("received files directory: %v", receivedFilesDir)
	// // fetch owned files directory from datastore
	// ciphertext, ciphertextMac, err = ParseCiphertextandTagFromDatastore((userdata.OwnedFilesDirLoc))
	// if err != nil {
	// 	userlib.DebugMsg("Fetching ciphertext from datastore failed.")
	// 	return nil, err
	// }

	// // check tag and decrypt from datastore
	// contentBytes, err = SymmetricTagAndDecrypt(userSourceKey, "storing owned files directory", ciphertext, ciphertextMac)
	// if err != nil {
	// 	userlib.DebugMsg("Symmetric decryption failed.")
	// 	return nil, err
	// }
	// json.Unmarshal(contentBytes, &ownedFilesDir)
	// userlib.DebugMsg("owned files directory: %v", ownedFilesDir)
	ownedFilesDir, receivedFilesDir, err = DecryptFileDirectories(userSourceKey, userdata.OwnedFilesDirLoc, userdata.ReceivedFilesDirLoc)

	// check if filename is in namespace
	_, inReceivedFilesDir := receivedFilesDir[filename]
	_, inOwnedFilesDir := ownedFilesDir[filename]
	if !inReceivedFilesDir && !inOwnedFilesDir {
		userlib.DebugMsg("Filename not in namespace.")
		return nil, err
	} else if inReceivedFilesDir {
		fileMetadataUUID = receivedFilesDir[filename]
	} else if inOwnedFilesDir {
		fileMetadataUUID = ownedFilesDir[filename]
	}

	// access file metadata and symmetric keys for decryption
	ciphertext, ciphertextMac, err := ParseCiphertextandTagFromDatastore(fileMetadataUUID)
	if err != nil {
		userlib.DebugMsg("Fetching ciphertext from datastore failed.")
		return nil, err
	}
	contentBytes, err := SymmetricTagAndDecrypt(userSourceKey, "storing file metadata", ciphertext, ciphertextMac)
	if err != nil {
		userlib.DebugMsg("Symmetric decryption failed.")
		return nil, err
	}
	json.Unmarshal(contentBytes, &fileMetadata)

	// decrypt initial file commit
	fileLocation := fileMetadata.FileLocation
	fileSourceKey := fileMetadata.FileSourceKey
	fileNumAppends := fileMetadata.NumAppends
	userlib.DebugMsg("%v location: %v, sourcekey: %v, numappends: %v", filename, fileLocation, fileSourceKey, fileNumAppends)

	ciphertext, ciphertextMac, err = ParseCiphertextandTagFromDatastore(fileLocation)
	if err != nil {
		userlib.DebugMsg("Fetching ciphertext from datastore failed.")
		return nil, err
	}
	contentBytes, err = SymmetricTagAndDecrypt(fileSourceKey, "storing file contents", ciphertext, ciphertextMac)
	if err != nil {
		userlib.DebugMsg("Symmetric decryption failed.")
		return nil, err
	}
	json.Unmarshal(contentBytes, &thisContent)
	userlib.DebugMsg("this content: %v", thisContent)
	content = append(content, thisContent...)
	userlib.DebugMsg("content so far now: %v", content)

	// decrypt rest of appended file commits
	for thisAppend := 1; thisAppend <= fileNumAppends; thisAppend++ {

		numAppends := IntToByteArray(thisAppend)
		fileAppendUUID, err := uuid.FromBytes(userlib.Hash(append(fileLocation[:], numAppends...))[:16])
		if err != nil {
			userlib.DebugMsg("fileUUID generation failed.")
			return nil, err
		}
		ciphertext, ciphertextMac, err = ParseCiphertextandTagFromDatastore(fileAppendUUID)
		if err != nil {
			userlib.DebugMsg("Fetching ciphertext from datastore failed.")
			return nil, err
		}
		contentBytes, err = SymmetricTagAndDecrypt(fileSourceKey, "storing file contents", ciphertext, ciphertextMac)
		if err != nil {
			userlib.DebugMsg("Symmetric decryption failed.")
			return nil, err
		}
		json.Unmarshal(contentBytes, &thisContent)
		userlib.DebugMsg("this content: %v", thisContent)
		content = append(content, thisContent...)
		userlib.DebugMsg("content so far: %v", content)
	}

	return content, nil
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
