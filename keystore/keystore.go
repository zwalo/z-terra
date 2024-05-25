package keystore

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/codahale/sss"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/console/prompt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/urfave/cli"
	"github.com/zwalo/z-nektar/zlog"
	"github.com/zwalo/z-terra/flag"
)

const (
	ShareJsonScheme = "passphrase"
	ShareJsonFile   = "share.sss"
)

type ShareJson struct {
	Index byte
	Share []byte
}

func Command(ctx *cli.Context) error {
	var privateKey *ecdsa.PrivateKey
	var err error
	isNew := ctx.GlobalBool(flag.NewFlage.Name)
	zlog.Head("start generate keystore")
	if isNew {
		zlog.Trace("you chose to generate new key")
		privateKey, err = crypto.GenerateKey()
		if err != nil {
			return err
		}

		path, err := prompt.Stdin.PromptInput("Enter path to save your private key file: ")
		if err != nil {
			return err
		}

		if err = crypto.SaveECDSA(path, privateKey); err != nil {
			if err = os.RemoveAll(path); err != nil {
				return err
			} else if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				return err
			} else if err = crypto.SaveECDSA(path, privateKey); err != nil {
				return err
			}
		}

		zlog.Debug(fmt.Sprintf("success save new private key file (path : %s)", path))
	} else {
		zlog.Trace("you chose to generate with your private key")
		isLoadFile, err := prompt.Stdin.PromptConfirm("Will you load your private key file?")
		if err != nil {
			return err
		}
		if isLoadFile {
			zlog.Trace("you chose to load your private key file")
		load_file:
			filePath, err := prompt.Stdin.PromptInput("Enter your private key file path: ")
			if err != nil {
				return err
			}
			privateKey, err = crypto.LoadECDSA(filePath)
			if err != nil {
				zlog.Error("Failed to load private key file: %v", err)
				goto load_file
			}
			zlog.Debug("success load private key file")
		} else {
			zlog.Trace("you chose to enter your private key")
		enter_pk:
			privateKeyHex, err := prompt.Stdin.PromptInput("Enter your private key (without 0x prefix): ")
			if err != nil {
				return err
			}

			privateKey, err = crypto.HexToECDSA(privateKeyHex)
			if err != nil {
				zlog.Error("Failed to convert private key: %v", err)
				goto enter_pk
			}

			zlog.Debug("success enter private key")
		}
	}

	// Create a new Ethereum keystore
	path, err := prompt.Stdin.PromptInput("Enter your new keystore path: ")
	if err != nil {
		return err
	}
	ks := keystore.NewKeyStore(path, keystore.StandardScryptN, keystore.StandardScryptP)

	// Get passphrase sss or single
	passphrase, err := makePassphrase()
	if err != nil {
		zlog.Error(fmt.Sprintf("Failed to make passphrase: %v", err))
		return err
	}

	account, err := ks.ImportECDSA(privateKey, passphrase)
	if err != nil {
		zlog.Error(fmt.Sprintf("Failed to import private key into keystore: %v", err))
		return err
	}

	zlog.Info(fmt.Sprintf("keystore file created for Ethereum address: %s", account.Address.Hex()))
	return nil
}

func makePassphrase() (string, error) {
enter_split:
	if num, err := prompt.Stdin.PromptInput("How many share of password? if less than 2, a normal password is generated. <splitN> : "); err != nil {
		return "", err
	} else if num == "" {
		goto enter_split
	} else if splitN, err := strconv.Atoi(num); err != nil {
		return "", err
	} else if splitN >= 10 || splitN < 0 {
		zlog.Warn("splitN is a positive integer less than 10.")
		goto enter_split
	} else {
		var (
			passphrase string
			err        error
		)
		switch {
		case splitN > 1:
			passphrase, err = sssPassphrase(splitN)
		default:
			passphrase, err = singlePassphrase()
		}

		if err != nil {
			return "", err
		}

		return passphrase, nil
	}
}

func sssPassphrase(splitN int) (string, error) {
	zlog.Trace(fmt.Sprintf("generate sss (split count : %d)", splitN))

enter_threshold:
	if num, err := prompt.Stdin.PromptInput(fmt.Sprintf("Enter the threshold, must be less than or equal to %v. <threshold>: ", splitN)); err != nil {
		return "", nil
	} else if num == "" {
		goto enter_threshold
	} else if threshold, err := strconv.Atoi(num); err != nil {
		return "", nil
	} else if threshold <= 1 || threshold > splitN {
		zlog.Warn("threshold must be greater than 1 and less than splitN.")
		goto enter_threshold
	} else {
		var (
			passphrase string
			shares     map[byte][]byte
			err        error
		)

	confirm_passphrase:
		yes, err := prompt.Stdin.PromptConfirm("Are you going to set this split keystore to be single unlockable?: ")
		if err != nil {
			return "", nil
		} else {
			if yes {
				zlog.Trace("you chose that SSS key can be unlockable by single passphrase (128bit or 192bit or 256bit)")
				if passphrase, err = singlePassphrase(); err != nil {
					return "", nil
				} else {
					if !(len(passphrase) == 16 || len(passphrase) == 24 || len(passphrase) == 32) {
						zlog.Warn("passphrase size must be 128bit or 192bit or 256bit")
						goto confirm_passphrase
					}
				}

			} else {
				zlog.Trace("you chose that SSS key can be not unlockable by single passphrase")
				passphrase, err = randPassphrase(32)
				if err != nil {
					return "", err
				}
			}
		}

		if shares, err = sss.Split(byte(splitN), byte(threshold), []byte(passphrase)); err != nil {
			return "", err
		}

		zlog.Debug(fmt.Sprintf("passphrase splited to %d (threshold=%d / single unlock = %v)", len(shares), threshold, yes))

		usbs := make(map[string]int)
		usbIndex := make(map[byte]string)
		for i := 1; i <= splitN; i++ {
		enter_path:
			if usbPath, err := prompt.Stdin.PromptInput(fmt.Sprintf("Enter the path to store the share (%d/%d) : ", i, splitN)); err != nil {
				return "", err
			} else if usbPath == "" {
				goto enter_path
			} else {
				usb := strings.TrimSpace(usbPath)
				if _, ok := usbs[usb]; ok {
					return "", fmt.Errorf("found equal usb directory")
				} else {
					usbs[usb] = i
					usbIndex[byte(i)] = usb

					if err := writeFile(usb, &ShareJson{Index: byte(i), Share: shares[byte(i)]}); err != nil {
						return "", err
					}
					zlog.Trace(fmt.Sprintf("%d share of passphrase transfered to %s", i, usb))
				}
			}
		}
		return passphrase, nil
	}
}

func singlePassphrase() (string, error) {
	passphrase, err := prompt.Stdin.PromptPassword("Enter your passphrase: ")
	return passphrase, err
}

func randPassphrase(n int) (string, error) {
	var runes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+{}|[]")
	b := make([]rune, n)
	max := new(big.Int).SetUint64(uint64(len(runes)))
	for i := range b {
		if n, err := rand.Int(rand.Reader, max); err != nil {
			return "", nil
		} else {
			b[i] = runes[n.Uint64()]
		}

	}
	return string(b), nil
}

func writeFile(dir string, shareJson *ShareJson) error {
	if err := encrypt(shareJson); err != nil {
		zlog.Error("share key json encrypt error, ", err)
		return err
	}

	dir = strings.TrimSpace(dir)
	endPath := path.Join(dir, ShareJsonScheme)
	if err := os.RemoveAll(endPath); err != nil {
		return err
	} else if err := os.MkdirAll(endPath, 0700); err != nil {
		return err
	} else if bytes, err := json.Marshal(shareJson); err != nil {
		return err
	} else if err := os.WriteFile(path.Join(endPath, ShareJsonFile), bytes, 0700); err != nil {
		return err
	}
	return nil
}

func encrypt(shareJson *ShareJson) error {
	if passphrase, err := prompt.Stdin.PromptPassword("Enter the password of new share: "); err != nil {
		return err
	} else {
		key := crypto.Keccak256([]byte(passphrase))[:len(shareJson.Share)]

		if block, err := aes.NewCipher([]byte(key)); err != nil {
			return err
		} else {
			ciphertext := make([]byte, block.BlockSize())
			block.Encrypt(ciphertext, shareJson.Share)
			shareJson.Share = ciphertext
		}
	}
	return nil
}
