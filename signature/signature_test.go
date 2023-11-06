package main

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"testing"
)

func Test_Sign(t *testing.T) {
	coderlangPrivateKey := "64946dbe03f1b8bcfacc95a7242da55e16cf2b9536d249414520f2cf8017ef1a"

	privateKey, err := crypto.HexToECDSA(coderlangPrivateKey)
	if err != nil {
		panic(fmt.Sprintf("privateKey %s err=%v", coderlangPrivateKey, err))
	}
	publicKey := privateKey.PublicKey

	// 打印公钥
	println("PublicKey: ", hex.EncodeToString(crypto.CompressPubkey(&publicKey)))
	println("Address: ", crypto.PubkeyToAddress(publicKey).Hex())
	// 要签名的数据
	data := []byte("小明借了100块钱给码农浪哥")

	// 对数据进行哈希
	hash := crypto.Keccak256Hash(data)
	fmt.Println("Hash: ", hex.EncodeToString(hash.Bytes()))
	// 使用私钥对数据哈希进行签名
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		fmt.Println("Error signing data:", err)
		return
	}

	// 打印签名
	fmt.Println("Signature: ", hex.EncodeToString(signature))
}
