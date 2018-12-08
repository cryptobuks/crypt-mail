package alice

import (
	"context"
	"cryptmail/protocol"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

type Alice struct {
	accounts map[string]*protocol.Account
	dirPath  string
	mu       sync.RWMutex
}

func NewAlice(dirPath string) *Alice {
	accounts := make(map[string]*protocol.Account)
	return &Alice{accounts: accounts, dirPath: dirPath}
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
	sessionId := in.SessionId
	tempPrivKey := ""
	tempPubKey := ""
	return &protocol.HandShakeResponse{SessionId: sessionId, PubKey: tempPubKey, PrivKey: tempPrivKey}, nil
}

func (a *Alice) Query(ctx context.Context, in *protocol.QueryRequest) (*protocol.QueryResponse, error) {
	sessionId := in.SessionId
	name := in.Name
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

func (a *Alice) Save(ctx context.Context, in *protocol.SaveRequest) (*protocol.SaveResponse, error) {
	sessionId := in.SessionId
	name := in.Name
	account := in.Account
	err := a.writeToFile(name, account)
	if err != nil {
		return &protocol.SaveResponse{SessionId: sessionId, Status: false, Msg: fmt.Sprintf("%v", err)}, err
	} else {
		return &protocol.SaveResponse{SessionId: sessionId, Status: true, Msg: ""}, nil
	}

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
