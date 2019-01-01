package alice

import (
	"context"
	"cryptmail/key"
	"cryptmail/protocol"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

const (
	CurrentVersion    uint32 = 1
	PasswordLength    int    = 32
	ExpirationSeconds int64  = 5 * 60
)

type Alice struct {
	accounts map[string]*protocol.Account
	unlocked map[uint64]map[string]*protocol.PrivAccount
	dirPath  string
	mu       sync.RWMutex
}

func NewAlice(dirPath string) *Alice {
	accounts := make(map[string]*protocol.Account)
	unlocked := make(map[uint64]map[string]*protocol.PrivAccount)
	return &Alice{accounts: accounts, dirPath: dirPath, unlocked: unlocked}
}

func (a *Alice) Init() error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if _, err := os.Stat(a.dirPath); os.IsNotExist(err) {
		if err = os.MkdirAll(a.dirPath, 0700); err != nil {
			return err
		}
	}
	r, _ := regexp.Compile(`CMAIL_KEYJSON-(\w+)\.json`)
	err := filepath.Walk(a.dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		if ok := r.MatchString(path); ok {
			accjson, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			var acc protocol.Account
			if err := json.Unmarshal(accjson, &acc); err != nil {
				return err
			}
			a.accounts[acc.Alias] = &acc
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (a *Alice) HandShake(ctx context.Context, in *protocol.HandShakeRequest) (*protocol.HandShakeResponse, error) {
	// sessionId to mark different temporal key-pair
	// implement temporal key-pair in next version
	sessionId := GenerateUUID()
	tempPrivKey := ""
	tempPubKey := ""
	return &protocol.HandShakeResponse{SessionId: sessionId, SPubKey: tempPubKey, SPrivKey: tempPrivKey}, nil
}

func (a *Alice) Query(ctx context.Context, in *protocol.QueryRequest) (*protocol.QueryResponse, error) {
	sessionId := in.SessionId
	name := in.Alias
	var queryAccounts []*protocol.Account
	if name == "" {
		for _, v := range a.accounts {
			queryAccounts = append(queryAccounts, v)
		}
	} else {
		if acc, ok := a.accounts[name]; ok {
			queryAccounts = append(queryAccounts, acc)
		}
	}
	return &protocol.QueryResponse{SessionId: sessionId, Accounts: queryAccounts}, nil
}

func (a *Alice) Create(ctx context.Context, in *protocol.CreateRequest) (*protocol.CreateResponse, error) {
	sessionId := in.SessionId
	name := in.Alias
	force := in.Force
	cipheredPhrase := in.Passphrase
	passphrase := cipheredPhrase
	priv, err := key.GenerateKey()
	if err != nil {
		return &protocol.CreateResponse{SessionId: sessionId}, errors.New("generate priv key error")
	}
	pub, err := priv.PubKey()
	if err != nil {
		return &protocol.CreateResponse{SessionId: sessionId}, errors.New("generate pub key error")
	}

	if _, ok := a.accounts[name]; ok && !force {
		return &protocol.CreateResponse{SessionId: sessionId}, errors.New(fmt.Sprintf("address alias %s has been used", name))
	}
	mac := hmac.New(sha256.New, []byte(passphrase))
	mac.Write([]byte(priv.ToWIF()))
	calcMac := mac.Sum(nil)
	macText := base64.StdEncoding.EncodeToString(calcMac)
	cipheredData, iv, err := a.encryptData([]byte(priv.ToWIF()), []byte(passphrase))
	cipherText := base64.StdEncoding.EncodeToString(cipheredData)
	ivText := base64.StdEncoding.EncodeToString(iv)
	account := &protocol.Account{Alias: name, PubKey: pub.ToWIF(), Cipher: selectAESAlgorithm(32),
		EncryptedPrivKey: cipherText, Iv: ivText, Mac: macText, Version: CurrentVersion}
	privAccount := &protocol.PrivAccount{Alias: name, PubKey: pub.ToWIF(), PrivKey: priv.ToWIF(),
		Expire: uint64(time.Now().Unix() + ExpirationSeconds)}
	a.accounts[name] = account
	a.unlocked[sessionId][name] = privAccount
	err = a.writeToFile(name, account)
	if err != nil {
		return &protocol.CreateResponse{SessionId: sessionId}, errors.New("save account date into file failed")
	} else {
		return &protocol.CreateResponse{SessionId: sessionId}, nil
	}
}

func (a *Alice) Import(ctx context.Context, in *protocol.ImportRequest) (*protocol.ImportResponse, error) {
	sessionId := in.SessionId
	name := in.Alias
	force := in.Force
	pubKey := in.PubKey
	privKey := in.PrivKey
	cipheredPhrase := in.Passphrase
	passphrase := cipheredPhrase
	if _, ok := a.accounts[name]; ok && !force {
		return &protocol.ImportResponse{SessionId: sessionId}, errors.New(fmt.Sprintf("address alias %s has been used", name))
	}
	mac := hmac.New(sha256.New, []byte(passphrase))
	mac.Write([]byte(privKey))
	calcMac := mac.Sum(nil)
	macText := base64.StdEncoding.EncodeToString(calcMac)
	cipheredData, iv, err := a.encryptData([]byte(privKey), []byte(passphrase))
	cipherText := base64.StdEncoding.EncodeToString(cipheredData)
	ivText := base64.StdEncoding.EncodeToString(iv)
	account := &protocol.Account{Alias: name, PubKey: pubKey, Cipher: selectAESAlgorithm(32),
		EncryptedPrivKey: cipherText, Iv: ivText, Mac: macText, Version: CurrentVersion}
	privAccount := &protocol.PrivAccount{Alias: name, PubKey: pubKey, PrivKey: privKey,
		Expire: uint64(time.Now().Unix() + ExpirationSeconds)}
	a.accounts[name] = account
	a.unlocked[sessionId][name] = privAccount
	err = a.writeToFile(name, account)
	if err != nil {
		return &protocol.ImportResponse{SessionId: sessionId}, errors.New("save account date into file failed")
	} else {
		return &protocol.ImportResponse{SessionId: sessionId}, nil
	}
}

func (a *Alice) Lock(ctx context.Context, in *protocol.LockRequest) (*protocol.LockResponse, error) {
	sessionId := in.SessionId
	name := in.Alias
	if _, ok := a.accounts[name]; !ok {
		msg := fmt.Sprintf("unknown account %s", name)
		return &protocol.LockResponse{SessionId: sessionId}, errors.New(msg)
	} else {
		unlocked, ok := a.unlocked[sessionId]
		if !ok {
			return &protocol.LockResponse{SessionId: sessionId},
				errors.New("unknown session id")
		}
		if _, ok := unlocked[name]; !ok {
			return &protocol.LockResponse{SessionId: sessionId}, nil
		} else {
			return &protocol.LockResponse{SessionId: sessionId},
				errors.New("no such account")
		}
	}
}

// should encrypt using priv-pub-key pair
// but not now
func (a *Alice) Unlock(ctx context.Context, in *protocol.UnlockRequest) (*protocol.UnlockResponse, error) {
	sessionId := in.SessionId
	name := in.Alias
	// todo: need decrypt cipher
	cipheredData := in.Passphrase
	passphare := cipheredData
	if acc, ok := a.accounts[name]; !ok {
		return &protocol.UnlockResponse{SessionId: sessionId}, errors.New("unknown name")
	} else {
		privAcc, err := a.decryptAccount(acc, []byte(passphare))
		if err != nil {
			return &protocol.UnlockResponse{SessionId: sessionId}, errors.New("decrypt account failed")
		}
		unlocked := a.unlocked[sessionId]
		unlocked[name] = privAcc
		//data, err := proto.Marshal(privAcc)
		if err != nil {
			return &protocol.UnlockResponse{SessionId: sessionId}, errors.New("proto marshal failed")
		}
		return &protocol.UnlockResponse{SessionId: sessionId}, nil
	}
}

func (a *Alice) hashPassphraseToFixLength(input []byte) []byte {
	sha_256 := sha256.New()
	sha_256.Write(input)
	result := sha_256.Sum(nil)
	return result[:PasswordLength]
}

func (a *Alice) decryptAccount(acc *protocol.Account, passphrase []byte) (*protocol.PrivAccount, error) {
	iv, err := base64.StdEncoding.DecodeString(acc.Iv)
	if err != nil {
		return nil, errors.New("iv decode base64 error")
	}
	cipherData, err := base64.StdEncoding.DecodeString(acc.EncryptedPrivKey)
	if err != nil {
		return nil, errors.New("privkey decode base64 error")
	}
	privKey, err := a.decryptData(cipherData, iv, passphrase)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, []byte(passphrase))
	mac.Write(privKey)
	calcMac := mac.Sum(nil)
	macData, err := base64.StdEncoding.DecodeString(acc.Mac)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(macData, calcMac) {
		return nil, errors.New("passphrase unmatched")
	}
	expiredTime := time.Now().Unix() + ExpirationSeconds
	// it is not right
	privAcc := &protocol.PrivAccount{Alias: acc.Alias, PubKey: acc.PubKey, PrivKey: string(privKey), Expire: uint64(expiredTime)}
	return privAcc, nil

}

func (a *Alice) encryptData(data, passphrase []byte) ([]byte, []byte, error) {
	seed := a.hashPassphraseToFixLength(passphrase)
	block, err := aes.NewCipher(seed)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	cipherdata := make([]byte, len(data))
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return []byte{}, []byte{}, err
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherdata, data)
	return cipherdata, iv, nil
}

func (a *Alice) decryptData(cipherData, iv, passphrase []byte) ([]byte, error) {
	seed := a.hashPassphraseToFixLength(passphrase)
	block, err := aes.NewCipher(seed)
	if err != nil {
		return []byte{}, err
	}
	data := make([]byte, len(cipherData))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, cipherData)
	return data, nil
}

func (a *Alice) generateFilename(name string) string {
	filename := fmt.Sprintf("CMAIL-KEYJSON-%s.json", name)
	return filename
}

func (a *Alice) writeToFile(name string, account *protocol.Account) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	filename := a.generateFilename(name)
	path := filepath.Join(a.dirPath, filename)
	keyjson, err := json.Marshal(account)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path, keyjson, 0600)
	return nil
}
