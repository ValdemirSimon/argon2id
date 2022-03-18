package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var DefaultConfig = &Config{
	Memory:     64 * 1024,
	Time:       1,
	Threads:    2,
	SaltLength: 16,
	KeyLength:  32,
}

func CreateNewHash(password string, config *Config) (hash string, err error) {
	salt, err := getRandomSalt(config.SaltLength)
	if err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, config.Time, config.Memory, config.Threads, config.KeyLength)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)
	hash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, config.Memory, config.Time, config.Threads, b64Salt, b64Key)
	return hash, nil
}
func ComparePasswordHash(password, hash string) (match bool, err error) {
	match, _, err = VerifyHash(password, hash)
	return match, err
}

func VerifyHash(password, hash string) (match bool, config *Config, err error) {
	config, salt, key, err := ParseHash(hash)
	if err != nil {
		return false, nil, err
	}
	otherKey := argon2.IDKey([]byte(password), salt, config.Time, config.Memory, config.Threads, config.KeyLength)
	keyLen := int32(len(key))
	otherKeyLen := int32(len(otherKey))
	if subtle.ConstantTimeEq(keyLen, otherKeyLen) == 0 {
		return false, config, nil
	}
	if subtle.ConstantTimeCompare(key, otherKey) == 1 {
		return true, config, nil
	}
	return false, config, nil
}

func ParseHash(hash string) (config *Config, salt, key []byte, err error) {
	hashSplitted := strings.Split(hash, "$")
	if len(hashSplitted) != 6 {
		return nil, nil, nil, errors.New("invalid hash")
	}
	if hashSplitted[1] != "argon2id" {
		return nil, nil, nil, errors.New("invalid hash variant")
	}
	var version int
	_, err = fmt.Sscanf(hashSplitted[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, errors.New("invalid hash version")
	}
	config = &Config{}
	_, err = fmt.Sscanf(hashSplitted[3], "m=%d,t=%d,p=%d", &config.Memory, &config.Time, &config.Threads)
	if err != nil {
		return nil, nil, nil, err
	}
	salt, err = base64.RawStdEncoding.Strict().DecodeString(hashSplitted[4])
	if err != nil {
		return nil, nil, nil, err
	}
	config.SaltLength = uint32(len(salt))
	key, err = base64.RawStdEncoding.Strict().DecodeString(hashSplitted[5])
	if err != nil {
		return nil, nil, nil, err
	}
	config.KeyLength = uint32(len(key))
	return config, salt, key, nil
}

func getRandomSalt(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
