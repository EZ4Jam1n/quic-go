package minPacketConn

import (
	"io/ioutil"
	"minlib/common"
	"minlib/minsecurity/identity"
	"minlib/security"
	"os"
)

func CreateNewIdentity(identity string, pwd string, path string) error {
	I := security.IdentityManager{}
	err := I.InitByPath(path)
	if err != nil {
		return err
	}
	_, err = I.CreateIdentityByName(identity, pwd)
	if err != nil {
		return err
	}
	return nil
}

func LoadIdentidy(filePath string, pwd string) (*identity.Identity, error) {
	f, err := os.Open(filePath)
	id := identity.Identity{}
	if err != nil {
		return &id, err
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		common.LogError("read IdFile Failed")
		return &id, err
	}
	err = id.Load(data, pwd)
	if err != nil {
		common.LogError("Load IdFile Failed")
		return &id, err
	}
	return &id, nil
}
