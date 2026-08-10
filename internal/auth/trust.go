package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type Store struct { Peers map[string]string `json:"peers"`; mu sync.Mutex }
func path() string { dir,_:=os.UserConfigDir(); dir=filepath.Join(dir,"cmd-chat"); _=os.MkdirAll(dir,0700); return filepath.Join(dir,"trusted_peers.json") }
func Load()*Store{s:=&Store{Peers:map[string]string{}};data,err:=os.ReadFile(path());if err==nil{_ = json.Unmarshal(data,s);if s.Peers==nil{s.Peers=map[string]string{}}};return s}
func (s *Store) Trust(id,publicKey string)error{s.mu.Lock();defer s.mu.Unlock();if id==""||publicKey==""{return errors.New("invalid trusted identity")};if old,ok:=s.Peers[id];ok&&old!=publicKey{return errors.New("trusted identity key mismatch")};s.Peers[id]=publicKey;data,err:=json.MarshalIndent(struct{Peers map[string]string `json:"peers"`}{s.Peers},"","  ");if err!=nil{return err};return os.WriteFile(path(),data,0600)}
func(s *Store) IsTrusted(id,publicKey string)bool{s.mu.Lock();defer s.mu.Unlock();return s.Peers[id]==publicKey}
